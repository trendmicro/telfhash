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

import sys
import itertools
import functools
import operator

# https://github.com/trendmicro/tlsh
import tlsh 


def get_combination(telfhash_data):

    #
    # TLSH hash is 70 characters long. if the telfhash is not 70
    # characters in length, exclude from the list
    #
    files_list = [x for x in list(telfhash_data.keys()) if telfhash_data[x]["telfhash"] is not None and len(telfhash_data[x]["telfhash"]) == 70]

    #
    # get the combination of all the possible pairs of filenames
    # we use itertools.combinations_with_replacement. this function
    # returns the combinations, but will treat the combination
    # (A,B) and (B,A) as equivalent
    #
    # the following list comprehension is to weed out the
    # combination pair of the same element, like (A,A)
    #
    ll = list(itertools.combinations_with_replacement(files_list, 2))
    files_combi = [x for x in ll if x[0] != x[1]]

    return files_combi


def get_distances(telfhash_data, files_combination):
    """Get the distance between each telfhash TLSH values

    Input:
        telfhash_data - dictionary of telfhash data with the keys being the
                       filename
        files_combination - a list of list. each component list contains
                            two files
    """

    distances = []

    for element in files_combination:
        file1 = element[0]
        file2 = element[1]
        distance = tlsh.diff(telfhash_data[file1]["telfhash"], telfhash_data[file2]["telfhash"])

        distances.append((file1, file2, distance))

    return distances


def condense(groups):
    """Condense the output list. some groups that appear are subset of
    another group. for example, the grouping output can be:

    ( ('A', 'B'),
      ('A', 'B', 'C'),
      ('A', 'B', 'C', 'D', 'E'),
      ('C', 'D', 'E', 'F'),
      ('G', 'H', 'I'))

    the condense() function will condense the above output to the
    following:

    ( ('G', 'H', 'I'),
      ('C', 'D', 'E', 'F'),
      ('A', 'B', 'C', 'D', 'E'))
    """
    group_set = [set(x) for x in groups]
    group_sorted = sorted(group_set, key=lambda x: len(x))

    condensed = []

    for i in range(len(group_sorted)):

        item = group_sorted[i]
        rest = group_sorted[i+1:]

        if len(rest) == 0:
            rest = group_sorted[:i]

        subset_check = [item.issubset(x) for x in rest]
        if not functools.reduce(operator.or_, subset_check, False):
            condensed.append(tuple(sorted(list(item))))

    return tuple(condensed)


def group_distances(distances, threshold=50):
    """
    Group files that are similar to each other according to their
    TLSH distance

    this works on the principle that when
        A is related to B; and
        B is related to C; therefore
        A is related to C

    Inputs:
        distances: list of tuples. each tuple is composed of
                   (fileA, fileB, TLSH_diff)

        threshold: maximum TLSH distance for two telfhashes to be
                   considered as related. defaults to 50
    """

    groups = set()

    for round1 in distances:
        A, B, dist1 = round1

        if dist1 <= threshold:
            group = set()
            group.update((A, B))

            for round2 in distances:
                if round1 == round2:
                    continue

                C, D, dist2 = round2
                if dist2 > threshold:
                    continue

                if (A in round2) or (B in round2):
                    group.update((C, D))

            if len(group) > 0:
                groups.add(tuple(sorted(tuple(group))))

    #
    # condense the output list. some groups that appear are subset of
    # another group. for example, the grouping output can be
    #
    # ( ('A', 'B'),
    #   ('A', 'B', 'C'),
    #   ('A', 'B', 'C', 'D', 'E'),
    #   ('C', 'D', 'E', 'F'),
    #   ('G', 'H', 'I'))
    #
    # the condense() function will condense the above output to the
    # following:
    #
    # ( ('G', 'H', 'I'),
    #   ('C', 'D', 'E', 'F'),
    #   ('A', 'B', 'C', 'D', 'E'))
    #
    condensed = condense(groups)

    # get the list of files that do not belong to any group
    files_list = [x[0] for x in distances]
    files_list += distances[-1:][0][:2]
    grouped_list = set([x for y in condensed for x in y])
    nogroup = [x for x in set(files_list) if x not in grouped_list]

    results = {}
    results["grouped"] = condensed
    results["nogroup"] = nogroup

    return results


def group(results, threshold=50):
    """Group the files according to how close their telfhashes are

    Input:
      results: a list of dicts containing the filename and their telfhash
    """

    #
    # `results` is a list of dicts. we now make a dictionary
    # with the key being the filename.
    #
    telfhash_data = {x["file"]:x for x in results}

    #
    # get all the possible file combinations, using the these conditions:
    # - removing duplicates
    # - these file combinations are equal: (A, B), (B, A)
    #
    files_combi = get_combination(telfhash_data)

    #
    # get the distances between all the file combinations
    #
    distances = get_distances(telfhash_data, files_combi)

    #
    # group according to distance. default distance threshold to be considered
    # in the same group is 50
    #
    groups = group_distances(distances, threshold)

    return groups


def main():
    return 0

if __name__ == "__main__":
    sys.exit(main())