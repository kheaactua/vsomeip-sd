#!/usr/bin/env python3

#
# CONFIDENTIAL - FORD MOTOR COMPANY
#
# This is an unpublished work, which is a trade secret, created in
# 2023.  Ford Motor Company owns all rights to this work and intends
# to maintain it in confidence to preserve its trade secret status.
# Ford Motor Company reserves the right to protect this work as an
# unpublished copyrighted work in the event of an inadvertent or
# deliberate unauthorized publication.  Ford Motor Company also
# reserves its rights under the copyright laws to protect this work
# as a published work.  Those having access to this work may not copy
# it, use it, or disclose the information contained in it without
# the written authorization of Ford Motor Company.
#

import argparse
import json


def build_parser(arg_parser):
    """Parse the command line arguments"""

    arg_parser.add_argument(
        "-c",
        action="store_true",
        dest="minify",
        help="Minify the resulting JSON file",
    )

    arg_parser.add_argument(
        "-o",
        "--output",
        type=str,
        action="store",
        dest="output_file",
        metavar="FILENAME",
        help="Output file for merged JSON",
    )

    arg_parser.add_argument(
        type=str,
        nargs="*",
        action="store",
        dest="input_files",
        metavar="INPUT_FILE",
        help="Files to merge",
    )


def merge(source, dest):
    """
    Merge a source dictionary into a dest dictionary.
    This can be problematic if the same key in the source
    and dest has a different type
    """

    for key, value in source.items():
        if isinstance(value, dict):
            node = dest.setdefault(key, {})
            merge(value, node)
        else:
            dest[key] = value

    return dest


def main():
    argument_parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Merge a collection of input JSON files into one output file",
    )
    build_parser(argument_parser)

    try:
        args = argument_parser.parse_args()
    except AttributeError as e:
        print(e, file=sys.stderr)
        exit(1)

    output_dict = {}
    for i in args.input_files:
        with open(i, "r") as f:
            content = json.load(f)
            merge(content, output_dict)

    with open(args.output_file, "w") as f:
        json.dump(output_dict, f, separators=(",", ":") if args.minify else None, indent=None if args.minify else 2)


if __name__ == "__main__":
    main()
