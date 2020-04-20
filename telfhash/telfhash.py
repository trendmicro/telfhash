#!/usr/bin/env python

'''
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
'''

# make it Python 2 compatible
from __future__ import print_function

import argparse
import os
import sys
import hashlib
import re
import functools
import operator
import glob
import json
import tlsh # https://github.com/trendmicro/tlsh
import elftools
from elftools.elf.elffile import ELFFile
from capstone import *

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import grouping

# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, 'VERSION')) as version_file:
    VERSION = version_file.read().strip()

EXCLUSIONS_REGEX = [
    r"^[_\.].*$",       # Function names starting with . or _
    "^.*64$",           # x64-64 specific functions
    "^str.*$",          # gcc significantly changes string functions depending on the target architecture, so we ignore them
    "^mem.*$"           # gcc significantly changes string functions depending on the target architecture, so we ignore them
]

EXCLUSIONS_STRINGS = [
    "__libc_start_main",    # main function
    "main",                 # main function
    "abort",                # ARM default
    "cachectl",             # MIPS default
    "cacheflush",           # MIPS default
    "puts",                 # Compiler optimization (function replacement)
    "atol",                 # Compiler optimization (function replacement)
    "malloc_trim"           # GNU extensions
]


# the op code and the mnemonic used for call functions to an absolute address
# across various architectures
CALL_LIST = {
    "x86": {
        "cs_arch": CS_ARCH_X86,
        "cs_mode": CS_MODE_32
    },
    "x64": {
        "cs_arch": CS_ARCH_X86,
        "cs_mode": CS_MODE_64
    },
    "ARM": {
        "cs_arch": CS_ARCH_ARM,
        "cs_mode": CS_MODE_ARM
    },
    "MIPS": {
        "cs_arch": CS_ARCH_MIPS,
        "cs_mode": CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN
    }
}


def perror(msg):
    print(msg, file=sys.stderr)


def build_exclude_list():
    EXCLUDE_LIST = {}
    EXCLUDE_LIST['simple'] = []
    EXCLUDE_LIST['regex'] = []

    excludes = {}
    excludes['simple'] = []
    excludes['regex'] = []

    for exclude_string in EXCLUSIONS_STRINGS:
        EXCLUDE_LIST['simple'].append(exclude_string)

    for exclude_re in EXCLUSIONS_REGEX:
        try:
            EXCLUDE_LIST['regex'].append(re.compile(exclude_re))
        except Exception as e:
            perror("Skipping '{}': {}".format(exclude_re, e.msg))

    return EXCLUDE_LIST


def can_exclude(symbol, exclude_list):

    if symbol in exclude_list['simple']:
        return True

    # use a list comprehension to generate an array of booleans if they match the list of supplied regexes
    # we then use functools.reduce() and operator.or_() to determine if at least one of the regex matched the
    # symbol we're searching
    re_matches = [True if x.search(symbol) else False for x in exclude_list['regex']]
    if functools.reduce(operator.or_, re_matches, False):
        return True

    return False


def get_hash(symbols_list):

    symbol_string = ",".join(symbols_list)
    encoded_symbol_string = symbol_string.encode('ascii')

    return tlsh.forcehash(encoded_symbol_string).lower()


def elf_get_imagebase(elf):
    i=0
    while elf.iter_segments():
        if (elf._get_segment_header(i)['p_type'] == 'PT_LOAD'):
            return elf._get_segment_header(i)['p_vaddr']
        i+=1

    return 0


def elf_is_static_stripped(elf):
    # If either PT_INTERP segment or .interp section is present, the executable is dynamic
    for s in elf.iter_segments():
        if (s['p_type'] == 'PT_INTERP'):
            return False

    # If .symtab is present, symbols were NOT stripped
    for s in elf.iter_sections():
        if (s['sh_type'] == 'SHT_SYMTAB'):
            return False

    return True


def get_ep_section_or_segment(elf):
    """Get the code section/segment where the entry point is located
    """

    # get the entry point
    ep = elf.header.e_entry

    # enumerate all the sections. the code section is where the entry point
    # falls in between the start and end address of the section
    for section in elf.iter_sections():
        start_offset = section.header.sh_addr
        end_offset = start_offset + section.header.sh_size - 1

        if (ep >= start_offset) and (ep <= end_offset):
            return section

    # if we reached this point, then we failed to get the code section using
    # the above method. we use the default '.text' section
    code_section_or_segment =  elf.get_section_by_name('.text')

    if code_section_or_segment:
        return code_section_or_segment

    for segment in elf.iter_segments():
        if segment['p_type'] == "PT_LOAD" and segment['p_flags'] == 5: # r-x segment
            return segment

    return code_section_or_segment


def extract_call_destinations(elf):
    symbols_list = []

    # get the code section or segment (if there's no section)
    code_section_or_segment = get_ep_section_or_segment(elf)

    # if we only got the segment, start extracting calls from the EP
    if type(code_section_or_segment) == elftools.elf.segments.Segment:
        ofs = elf.header.e_entry
        code_data = code_section_or_segment.data()[ofs - code_section_or_segment['p_vaddr']:]
    # otherwise we use the code section
    else:
        ofs = elf_get_imagebase(elf) + code_section_or_segment['sh_offset']
        code_data = code_section_or_segment.data()

    # get the architecture of our ELF file.
    # the disassembly and the call opcode and mnemonic will be based on the
    # determined architecture, as defined by the CALL_LIST dict above
    arch = elf.get_machine_arch()

    # in case we have not specified the opcode, mnemonic, and the
    # capstone arch and mode, skip
    if arch not in CALL_LIST:
        return []

    # TODO: automatically identify the architecture the binary was compiled to
    md = Cs(CALL_LIST[arch]["cs_arch"], CALL_LIST[arch]["cs_mode"])

    if code_section_or_segment is not None:
        # TODO: handle UPX-packed binaries as they have no sections so we should go straight to segment offset
        for i in md.disasm(code_data, ofs):
            if arch in ("x86", "x64") and i.mnemonic == "call":
                # Consider only call to absolute addresses
                if i.op_str.startswith('0x'):
                    address = i.op_str[2:] # cut off '0x' prefix
                    if not address in symbols_list:
                        symbols_list.append(address)
                        
            elif arch == "ARM" and i.mnemonic.startswith("bl"):
                if i.op_str.startswith('#0x'):
                    address = i.op_str[3:]
                    if not address in symbols_list:
                        symbols_list.append(address)

            elif arch == "MIPS" and i.mnemonic == "lw":
                if i.op_str.startswith("$t9, "):
                    address = i.op_str[8:-5]
                    if not address in symbols_list:
                        symbols_list.append(address)

    return symbols_list


def extract_symbols(filepath, **kwargs):
    """Returns a list of symbols read from the ELF file, excluding those
    symbols found in our exclusion list
    """

    debug = False

    if "debug" in kwargs and kwargs["debug"] is True:
        debug = True

    if "exclude_list" not in kwargs:
        exclude_list = build_exclude_list()
    else:
        exclude_list = kwargs["exclude_list"]

    fh = open(filepath, 'rb')

    try:
        elf = ELFFile(fh)
    except:
        if not fh.closed:
            fh.close()
        raise

    # Types: 'SHT_SYMTAB', 'SHT_DYNSYM', 'SHT_SUNW_LDYNSYM' 

    if debug:
        print(elf['e_ident']['EI_CLASS'])

    symtab=''
    for s in elf.iter_sections():
        if (s['sh_size'] <= 0):
            continue

        if (s['sh_type'] == 'SHT_DYNSYM'):
            symtab = s
            break # dynamic symbol table has higher priority

        elif (s['sh_type'] == 'SHT_SYMTAB'):
            symtab = s
            break

    if (not symtab):
        call_destinations = extract_call_destinations(elf)
        fh.close()

        if debug:
            print("Statically compiled")
            print("{} call addresses considered".format(len(call_destinations)))

        return call_destinations

    if debug:
        print('{} symbols found'.format(symtab.num_symbols()))

    symbols_list = []
    i=0
    for sym in symtab.iter_symbols():
        sym_type = sym.entry['st_info']['type']
        sym_bind = sym.entry['st_info']['bind']
        sym_visibility = sym.entry['st_other']['visibility']

        if (sym_type != 'STT_FUNC' or
            sym_bind != 'STB_GLOBAL' or
            sym_visibility != 'STV_DEFAULT' or
            len(sym.name) <= 0):
            continue

        # Function name exceptions
        if can_exclude(sym.name, exclude_list):
            continue

        i += 1
        symbols_list.append(sym.name.lower()) # lowercase
    
    # sort the symbol list
    symbols_list.sort()

    # creates the symbol string
    syms = ",".join(symbols_list)

    if debug:
        print("{} symbols considered:\n{}".format(i, syms))

    fh.close()
    return symbols_list


def fopen(fname):
    try:
        fh = open(fname, 'rb')
    except:
        perror('{}: could not open file for reading'.format(fname))
    return fh


def expand_filepath(input_filepath, recursive=False):
    """get the list of files, expanding on wildcards if necessary
    (using glob.glob)"""

    files_list = []

    if recursive is True:
        for i in os.walk(input_filepath):
            for j in i[2]:
                files_list.append("{}".format(os.path.join(i[0], j)))

    else:
        for filepath in glob.glob(input_filepath):
            if os.path.isfile(filepath):
                files_list.append(filepath)

    return files_list


def get_max_len(files_list):
    """Get the length of the file with the longest filename"""
    ret = 0

    if len(files_list) > 0:
        filename_lengths = [len(x) for x in files_list]
        max_len = max(filename_lengths)
        ret = max_len

    return ret


def get_args():
    parser = argparse.ArgumentParser(prog="telfhash")
    parser.add_argument('-g', '--group', help='Group the files according to how close their telfhashes are', action='store_true')
    parser.add_argument('-t', '--threshold', default="50", help='Minimum distance between telfhashes to be considered as related. Only works with -g/--group. Defaults to 50')
    parser.add_argument('-r', '--recursive', default=False, help='Deep dive into all the subfolders. Input should be a folder', action='store_true')
    parser.add_argument('-o', '--output', default=None, help='Output file')
    parser.add_argument('-f', '--format', default=None, help='Log output format. Accepts tsv or json. If -o/--output is not specified, formatted output is printed on stdout')
    parser.add_argument('-d', '--debug', help='Print debug messages', action='store_true')
    parser.add_argument('-v', '--version', help='Print version', action='version', version="%(prog)s {}".format(VERSION))
    parser.add_argument('files', help='Target ELF file(s). Accepts wildcards', default=[], nargs='+')
    args = parser.parse_args()

    # after parsing, args.files is a list
    args.files_list = []
    for f in args.files:
        args.files_list += expand_filepath(f, args.recursive)

    # get the length of the longest filename. this is helpful later when
    # printing the telfhashes in STDOUT, where we'll use the `max_len` to
    # vertically align the telfhash column
    args.max_len = get_max_len(args.files_list)

    if args.threshold.isdigit():
        args.threshold = int(args.threshold)
    else:
        perror("'{}' is an invalid value for threshold. defaulting the threshold to 50.\n".format(args.threshold))
        args.threshold = 50

    # convert our args into a dictionary
    params = args.__dict__

    return params


def telfhash_single(filepath, **kwargs):
    result = {}
    result["file"] = filepath
    result["telfhash"] = '-'
    result["msg"] = ""

    debug = False

    if "debug" in kwargs and kwargs["debug"] is True:
        debug = True

    if "exclude_list" not in kwargs:
        exclude_list = build_exclude_list()
    else:
        exclude_list = kwargs["exclude_list"]

    try:
        symbols_list = extract_symbols(filepath, debug=debug, exclude_list=exclude_list)
    except FileNotFoundError as e:
        symbols_list = None
        result["msg"] = e.strerror
    except elftools.common.exceptions.ELFError:
        symbols_list = None
        result["msg"] = "Could not parse file as ELF"
    except:
        symbols_list = None
        result["msg"] = "Unknown error"

    if symbols_list is not None:
        if len(symbols_list) > 0:
            h = get_hash(symbols_list)

            # if the hash of our symbols generated a blank string
            if len(h) == 0:
                h = '-'

            result["telfhash"] = h
        else:
            result["msg"] = "No symbols found"
    else:
        if len(result["msg"]) == 0:
            result["msg"] = "No symbols found"

    return result


def telfhash(*paths, **kwargs):
    """Get the telfhash of specified files. Accepts wildcards

    Args:
        paths       One or more file paths to get telfhashes on. Accepts
                    wildcards. Module uses glob.glob for file expansion

        recursive   [Optional] Boolean. Recursively find files to get the
                    telfhash. Defaults to False

        debug       [Optional] Boolean. Display debug messages. Defaults to
                    False

    Returns:
        A list of dicts, each dict contains the telfhash data of each file.
    """

    # default values
    results = []
    recursive = False
    debug = False
    files_list = []

    if len(paths) == 0:
        return results

    if "recursive" in kwargs and kwargs["recursive"] is True:
        recursive = True

    if "debug" in kwargs and kwargs["debug"] is True:
        debug = True

    exclude_list = build_exclude_list()

    for path in paths:
        files_list += expand_filepath(path, recursive=recursive)

    for f in files_list:
        result = telfhash_single(f, debug=debug, exclude_list=exclude_list)
        results.append(result)

    return results


def group(telfhash_results, threshold=50):
    """Group the files according to the TLSH distances between the telfhashes
    of the files

    Args:
        telfhash_results: The output of the telfhash.telfhash function call. List
                         of telfhash data of the files
        threshold:       [Optional] The minimum TLSH distance between telfhashes
                         for the files to be considered as related

    Returns:
        Tuple of tuples, each member tuple is one group
    """
    groups = grouping.group(telfhash_results, threshold=threshold)

    return groups


def output_format_tsv(args, results):
    if args['output'] is None:
        # output to stdout
        for result in results:
            print("{}\t{}".format(result['file'], result['telfhash']))

    else:
        with open(args['output'], 'w') as fh:
            for result in results:
                fh.write("{}\t{}\n".format(result['file'], result['telfhash']))


def output_format_json(args, results):
    json_output = json.dumps(results)

    if args['output'] is None:
        # output to stdout
        print("{}".format(json_output))

    else:
        with open(args['output'], 'w') as fh:
            fh.write("{}\n".format(json_output))


def print_hashes(args):

    exclude_list = build_exclude_list()

    results = []
    for filepath in args["files_list"]:
        result = telfhash_single(filepath, debug=args["debug"], exclude_list=exclude_list)
        results.append(result)

        # the fancy formatting is done so that we could properly vertically
        # align the telfhashes in the second column. we're using the `max_len`
        # value computed before in the get_args() function
        #
        # data is printed as soon as the data is obtained so that the user sees
        # data right away, and it makes the console more active.
        # only go this path if args['output']=None and args['format']=None
        if args['output'] is None and args['format'] is None:
            if result["telfhash"] is not None:
                print("{:<{max_len}}  {}".format(result["file"], result["telfhash"], max_len=args["max_len"]))
            else:
                print('{:<{max_len}}  {msg}'.format(filepath, max_len=args["max_len"], msg=result["msg"]))

    if args['format'] == 'tsv':
        output_format_tsv(args, results)

    elif args['format'] == 'json':
        output_format_json(args, results)

    if args['group'] and len(results) > 1:
        groups = grouping.group(results, threshold=args['threshold'])

        print()
        for i in range(len(groups["grouped"])):
            print("Group {}:".format(i+1))
            for f in groups["grouped"][i]:
                print("    {}".format(f))

        if len(groups["nogroup"]) > 0:
            print("Ungrouped:")
            for f in groups["nogroup"]:
                print("    {}".format(f))


    print()


def _main():

    args = get_args()

    if len(args["files_list"]) == 0:
        perror("No files found")
        return 1

    print_hashes(args)


def main():
    return _main()


if __name__ == "__main__":
    sys.exit(main())
