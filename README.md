# Trend Micro ELF Hash (telfhash)

telfhash is symbol hash for ELF files, just like imphash is imports hash for PE files.

## Installation

### Requirements

telfhash uses TLSH in generating the hash. TLSH must be installed in your system in order for telfhash to work.

You can install TLSH from here:

* [https://github.com/trendmicro/tlsh/](https://github.com/trendmicro/tlsh/)

The TLSH git repo has detailed instructions on how to compile and install the TLSH binaries and libraries. Don't forget to also install the TLSH Python library. telfhash uses the TLSH Python library to generate the actual hash.

### Installing

Clone the telfhash repository from here:

* [https://github.com/trendmicro/telfhash](https://github.com/trendmicro/telfhash)

Use the `setup.py` to install the telfhash library:

    python setup.py install

## Usage

If the TLSH Python library is not installed, telfhash will generate an exception error.

### Command line

If telfhash was installed via the `python setup.py install` command, the `telfhash` executable will by made available.

    $ telfhash -h
    usage: telfhash.py [-h] [-g] [-t THRESHOLD] [-r] [-d] files [files ...]

    positional arguments:
      files                 Target ELF file(s). Accepts wildcards

    optional arguments:
      -h, --help            show this help message and exit
      -g, --group           Group the files according to how close their telfhashes
                            are
      -t THRESHOLD, --threshold THRESHOLD
                            Minimum distance betweeen telfhashes to be considered
                            as related. Only works with -g/--group. Defaults to 50
      -r, --recursive       Deep dive into all the subfolders. Input should be a
                            folder
      -d, --debug           Print debug messages

    $ telfhash /bin/trace*
    /bin/tracepath    09d097025c0b40af18cb0c08ac3f2f5df100d850483bc1404f108809113290a2d6ae4f
    /bin/traceroute   65e02002d9b9552f56f35e709caf6fa57115f841e83b87148f04b592c023542ed0549f
    /bin/traceroute6  65e02002d9b9552f56f35e709caf6fa57115f841e83b87148f04b592c023542ed0549f

    $ telfhash -g /sbin/ip*
    /sbin/ip                        33c15268ac66484d58be0e68ed2d7e68c25b5b97edf02b10dff4c412d2c3586725f01b
    /sbin/ip6tables                 083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/ip6tables-legacy          083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/ip6tables-legacy-restore  083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/ip6tables-legacy-save     083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/ip6tables-restore         083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/ip6tables-save            083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/ipmaddr                   7dc08c0a6622ad4b2af66e781c3322864248e073b06ccb56aaaf854088062091c6011c
    /sbin/ipset                     e4a0029085e66bce4ed2146959136540409454e38028d780613002a6d70154d5023d6a
    /sbin/iptables                  083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/iptables-apply            -
    /sbin/iptables-legacy           083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/iptables-legacy-restore   083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/iptables-legacy-save      083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/iptables-restore          083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/iptables-save             083169fc5722ee8734bfb9357cf23b41a5092db0b9a8d0a95d08d743464636ca143c66
    /sbin/iptstate                  1ef02223f4318ca385920c9910f975a131268721a1dbb80dff038e758bad21e65718cf
    /sbin/iptunnel                  d5c08c4aa612ad5b3ae72e781c3330868248e0b2b05c8b52aa2a854089062090c60518

    Group 1:
        /sbin/ipmaddr
        /sbin/iptunnel
    Group 2:
        /sbin/ip6tables
        /sbin/ip6tables-legacy
        /sbin/ip6tables-legacy-restore
        /sbin/ip6tables-legacy-save
        /sbin/ip6tables-restore
        /sbin/ip6tables-save
        /sbin/iptables
        /sbin/iptables-legacy
        /sbin/iptables-legacy-restore
        /sbin/iptables-legacy-save
        /sbin/iptables-restore
        /sbin/iptables-save
    Cannot be grouped:
        /sbin/iptstate
        /sbin/ipset
        /sbin/ip

### Python module

    >>> import telfhash
    >>> import pprint
    >>> telfhash.telfhash("/bin/ping")
    {'file': '/bin/ping', 'telfhash': '6901d303587a847f9aa30ce44c3f3f5c6101e9525eb2d354cf1297948022b40aa4a99f', 'msg': ''}
    >>>
    >>> results = telfhash.telfhash("telfhash/tests/samples/hdumps/*")
    >>> groups = telfhash.group(results)
    >>> pprint.pprint(groups)
    {'grouped': (('telfhash/tests/samples/hdumps/hdump_32_so_stat_stripped',
                  'telfhash/tests/samples/hdumps/hdump_32_stat_stripped'),
                 ('telfhash/tests/samples/hdumps/hdump_64_so_stat_stripped',
                  'telfhash/tests/samples/hdumps/hdump_64_stat_stripped'),
                 ('telfhash/tests/samples/hdumps/hdump_32_so_stat',
                  'telfhash/tests/samples/hdumps/hdump_32_stat',
                  'telfhash/tests/samples/hdumps/hdump_64_so_stat',
                  'telfhash/tests/samples/hdumps/hdump_64_stat',
                  'telfhash/tests/samples/hdumps/hdump_static'),
                 ('telfhash/tests/samples/hdumps/hdump',
                  'telfhash/tests/samples/hdumps/hdump32',
                  'telfhash/tests/samples/hdumps/hdump_32_dyn',
                  'telfhash/tests/samples/hdumps/hdump_32_dyn_stripped',
                  'telfhash/tests/samples/hdumps/hdump_32_so_dyn',
                  'telfhash/tests/samples/hdumps/hdump_32_so_dyn_stripped',
                  'telfhash/tests/samples/hdumps/hdump_64_dyn',
                  'telfhash/tests/samples/hdumps/hdump_64_dyn_stripped',
                  'telfhash/tests/samples/hdumps/hdump_64_so_dyn',
                  'telfhash/tests/samples/hdumps/hdump_64_so_dyn_stripped',
                  'telfhash/tests/samples/hdumps/hdump_dynamic',
                  'telfhash/tests/samples/hdumps/hdump_stripped')),
     'nogroup': []}
    >>>
    >>> telfhash.telfhash("samples/LinuxMoose/LinuxMoose.arm7.2015.0.bin")
    {'file': 'samples/LinuxMoose/LinuxMoose.arm7.2015.0.bin', 'telfhash': None, 'msg': 'No symbols found'}
    >>> telfhash.telfhash("/bin/ls", "/bin/lsattr")
    [{'file': '/bin/ls', 'telfhash': '1ff0994248230af71762c8b15c0533da9a208b2656e5bf302f1985d04e2a5be779284f', 'msg': ''}, {'file': '/bin/lsattr', 'telfhash': '69c08017dd0fe4f35dd90d589c07380ae7dee06057b9d7400d3c46c1755058c5d5555d', 'msg': ''}]

## Publications

[Grouping Linux IoT Malware Samples With Trend Micro ELF Hash aka telfash](https://blog.trendmicro.com/trendlabs-security-intelligence/) - Trend Micro Blog, 2020 April 20th.
