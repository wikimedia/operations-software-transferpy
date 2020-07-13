#!/usr/bin/python3

import argparse
import sys
import logging
from transferpy.Transferer import Transferer


class RawOption(argparse.HelpFormatter):
    """Class to format ArgumentParser help"""

    def _split_lines(self, text, width):
        """
        Formats the given text by splitting the lines at '\n'.
        Overrides argparse.HelpFormatter._split_lines function.

        :param text: help text passed by ArgumentParser.HelpFormatter
        :param width: console width passed by argparse.HelpFormatter
        :return: argparse.HelpFormatter._split_lines function
        with new split text argument.
        """
        if text.startswith('raw|'):
            return text[4:].splitlines()
        return argparse.HelpFormatter._split_lines(self, text, width)


def setup_logger(verbose):
    """
    Setup a logger named transferpy. The logger level
    is set based on the verbose value. If verbose is true,
    set the logger to DEBUG level, else INFO level.
    This logger is globally available in the package and
    can be accessed using logging.getLogger('transferpy').

    :param verbose: verbose boolean variable
    :return:
    """
    logger = logging.getLogger('transferpy')
    handler = logging.StreamHandler(stream=sys.stdout)
    if verbose:
        handler.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s  %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


def parse_arguments():
    """
    Parses the input parameters.

    :return: parser object
    """
    parser = argparse.ArgumentParser(description="transfer is a Python 3 framework intended to "
                                                 "move large files or directory trees between WMF "
                                                 "production hosts in an efficient way.",
                                     epilog="Thank you! Full documentation at: "
                                            "https://wikitech.wikimedia.org/wiki/Transfer.py",
                                     formatter_class=RawOption)
    parser.add_argument("--port", type=int, default=0,
                        help="Port used for netcat listening on the receiver machine. "
                             " By default, transfer selects a free port available in the receiver"
                             " machine from the range 4400 to 4500")
    parser.add_argument("--type", choices=['file', 'xtrabackup', 'decompress'],
                        dest='transfer_type', default='file',
                        help="raw|file: regular file or directory recursive copy (Default)\n"
                             "xtrabackup: runs mariabackup on source\n"
                             "decompress: a tarball is transmitted as is and decompressed on target")
    parser.add_argument("source",
                        help="Fully qualified domain of the host where the files to be copied "
                             "are currently located, the symbol ':', and a file or directory "
                             "path of such files (e.g. sourcehost.wm.org:/srv ). "
                             "There can be only one source host and path.")
    parser.add_argument("target", nargs='+',
                        help="Fully qualified domain of the hosts (separated by spaces) "
                             "where the files to be copied, each one with its "
                             "destination absolute path directory, separated by ':'."
                             "There must be at least one target. If more than one target "
                             "is defined, it will be copied to all of them. The target path"
                             " MUST be a directory.")

    compress_group = parser.add_mutually_exclusive_group()
    compress_group.add_argument('--compress', action='store_true', dest='compress',
                                help="Use pigz to compress stream using gzip format "
                                     "(ignored on decompress mode) (Default)")
    compress_group.add_argument('--no-compress', action='store_false', dest='compress',
                                help="Do not use compression on streaming")
    parser.set_defaults(compress=True)

    encrypt_group = parser.add_mutually_exclusive_group()
    encrypt_group.add_argument('--encrypt', action='store_true', dest='encrypt',
                               help="Enable compression - send data using openssl and "
                                    "algorithm chacha20 (Default)")
    encrypt_group.add_argument('--no-encrypt', action='store_false', dest='encrypt',
                               help="Disable compression - send data using an unencrypted stream")
    parser.set_defaults(encrypt=True)

    checksum_group = parser.add_mutually_exclusive_group()
    checksum_group.add_argument('--checksum', action='store_true', dest='checksum',
                                help="Generate a checksum of files before transmission which will be "
                                     "used for checking integrity after transfer finishes. "
                                     "(This only works for file transfers) (Default)")
    checksum_group.add_argument('--no-checksum', action='store_false', dest='checksum',
                                help="Disable checksums")
    parser.set_defaults(checksum=True)

    parser.add_argument('--stop-slave', action='store_true', dest='stop_slave',
                        help="Only relevant if on xtrabackup mode: attempt to stop slave on the mysql instance "
                             "before running xtrabackup, and start slave after it completes to try to speed up "
                             "backup by preventing many changes queued on the xtrabackup_log. "
                             "By default, it doesn't try to stop replication.")

    parser.add_argument('--verbose', action='store_true',
                        help="Outputs relevant information about transfer + information about Cuminexecution."
                             " By default, the output contains only relevant information about the transfer.")
    return parser


def split_target(target):
    """
    Splits the target string to target hostname and path

    :param target: string in the form of hostname:target-path
    :return: if successful: target hostname, path
             else system exit
    """
    if target.count(':') == 1:
        host, path = target.split(':')
        if host and path:
            return host, path
    logger = logging.getLogger('transferpy')
    logger.error("Source/Destination must contain the fully qualified name of the host"
                 " and absolute path separated by a colon")
    sys.exit(2)


def option_parse():
    """
    Parses the input parameters and returns them as a list.

    :return: sender host, sender path, receiver hosts, receiver paths, other options
    """
    options = parse_arguments().parse_args()
    setup_logger(options.verbose)
    source_host, source_path = split_target(options.source)
    target_hosts = []
    target_paths = []
    for target in options.target:
        target_host, target_path = split_target(target)
        target_hosts.append(target_host)
        target_paths.append(target_path)
    other_options = {
        'port': options.port,
        'type': options.transfer_type,
        'compress': True if options.transfer_type == 'decompress' else options.compress,
        'encrypt': options.encrypt,
        'checksum': False if not options.transfer_type == 'file' else options.checksum,
        'stop_slave': False if not options.transfer_type == 'xtrabackup' else options.stop_slave,
        'verbose': options.verbose
    }
    return source_host, source_path, target_hosts, target_paths, other_options


def main():
    """
    Main of transfer framework.

    :return: system exit
    """
    (source_host, source_path, target_hosts, target_paths, other_options) = option_parse()
    t = Transferer(source_host, source_path, target_hosts, target_paths, other_options)
    result = t.run()
    sys.exit(max(result))


if __name__ == "__main__":
    main()
