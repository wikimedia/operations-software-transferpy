#!/usr/bin/python3

import argparse
import configparser
import sys
import logging
from transferpy.Transferer import Transferer


CONFIG_FILE = '/etc/transferpy/transferpy.conf'


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


def to_bool(value):
    """
    Convert the given string to boolean value.

    :param value: value needs to be converted
    :return: boolean value if given value is convertible
    else ValueError
    """
    valid = {'true': True, 't': True, '1': True,
             'false': False, 'f': False, '0': False,
             }

    if isinstance(value, bool):
        return value

    lower_value = value.lower()
    if lower_value in valid:
        return valid[lower_value]
    else:
        raise ValueError('invalid literal for boolean : "{}"'.format(value))


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
    parser.add_argument("--config", dest='config_file',
                        help="Configuration file path. If found, it will set as the execution "
                             "defaults unless overridden on the command line. Default: {}".
                        format(CONFIG_FILE), default=CONFIG_FILE)
    parser.add_argument("--port", type=int, default=None,
                        help="Port used for netcat listening on the receiver machine. "
                             " By default, transfer selects a free port available in the receiver"
                             " machine from the range 4400 to 4500")
    parser.add_argument("--type", choices=['file', 'xtrabackup', 'decompress'],
                        dest='transfer_type', default=None,
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
    parser.set_defaults(compress=None)

    encrypt_group = parser.add_mutually_exclusive_group()
    encrypt_group.add_argument('--encrypt', action='store_true', dest='encrypt',
                               help="Enable compression - send data using openssl and "
                                    "algorithm chacha20 (Default)")
    encrypt_group.add_argument('--no-encrypt', action='store_false', dest='encrypt',
                               help="Disable compression - send data using an unencrypted stream")
    parser.set_defaults(encrypt=None)

    checksum_group = parser.add_mutually_exclusive_group()
    checksum_group.add_argument('--checksum', action='store_true', dest='checksum',
                                help="Generate a checksum of files before transmission which will be "
                                     "used for checking integrity after transfer finishes. "
                                     "(This only works for file transfers) (Default)")
    checksum_group.add_argument('--no-checksum', action='store_false', dest='checksum',
                                help="Disable checksums")
    parser.set_defaults(checksum=None)
    parallel_checksum_group = parser.add_mutually_exclusive_group()
    parallel_checksum_group.add_argument('--parallel-checksum', action='store_true', dest='parallel_checksum',
                                         help="Generate checksum parallel to the transmission for data "
                                              "integrity check (ignored if --checksum is enabled). "
                                              "--parallel_checksum is faster than --checksum but less reliable")
    parallel_checksum_group.add_argument('--no-parallel-checksum', action='store_false', dest='parallel_checksum',
                                         help="Disable parallel checksum (Default)")
    parser.set_defaults(parallel_checksum=None)
    parser.add_argument('--stop-slave', action='store_true', dest='stop_slave', default=None,
                        help="Only relevant if on xtrabackup mode: attempt to stop slave on the mysql instance "
                             "before running xtrabackup, and start slave after it completes to try to speed up "
                             "backup by preventing many changes queued on the xtrabackup_log. "
                             "By default, it doesn't try to stop replication.")

    parser.add_argument('--verbose', action='store_true', default=None,
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
    try:
        host, path = [t.strip() for t in target.split(':')]
        if not host or not path:
            raise ValueError("Either host or path is empty")
    except ValueError:
        logger = logging.getLogger('transferpy')
        logger.error("The host and path are not correctly "
                     "separated by a colon at {}".format(target))
        sys.exit(2)

    return host, path


def parse_configurations(config_file):
    """
    Parses the configuration file parameters.

    :return: parser object
    """
    config = configparser.ConfigParser()
    config.read(config_file)
    return config['DEFAULT']


def assign_default_options(options):
    """
    Assign default values if the given options dictionary is missing
    some required arguments.

    :param options: given options
    :return:
    """
    default_options = {'port': 0, 'transfer_type': 'file',
                       'compress': True, 'encrypt': True, 'checksum': True,
                       'parallel_checksum': False, 'stop_slave': False,
                       'verbose': False}
    for opt, defval in default_options.items():
        if isinstance(defval, bool):
            options[opt] = to_bool(options[opt]) if opt in options else defval
        elif isinstance(defval, int):
            options[opt] = int(options[opt]) if opt in options else defval
        else:
            options[opt] = options[opt] if opt in options else defval
    return options


def option_parse():
    """
    Parses the input parameters and returns them as a list.

    :return: sender host, sender path, receiver hosts, receiver paths, other options
    """
    # Take arguments from both command line and config file.
    arguments = parse_arguments().parse_args()
    cli_args = vars(arguments)
    conf_args = dict(parse_configurations(arguments.config_file))
    # Make checksum False if --parallel-checksum is given as command line
    # argument and --no-checksum is not mentioned
    if cli_args['parallel_checksum'] and cli_args['checksum'] is None:
        conf_args['checksum'] = False
    # Give first preference to command line arguments.
    conf_args.update({k: v for k, v in cli_args.items() if v is not None})
    # If both command line and config does not provide any preference
    # assign program default values.
    options = assign_default_options(conf_args)

    setup_logger(options['verbose'])
    # Take source argument from command line only
    source_host, source_path = split_target(arguments.source)
    target_hosts = []
    target_paths = []
    # Take target argument from command line only
    for target in arguments.target:
        target_host, target_path = split_target(target)
        target_hosts.append(target_host)
        target_paths.append(target_path)
    other_options = {
        'port': options['port'],
        'type': options['transfer_type'],
        'compress': True if options['transfer_type'] == 'decompress' else options['compress'],
        'encrypt': options['encrypt'],
        'checksum': False if not options['transfer_type'] == 'file' else options['checksum'],
        'parallel_checksum': False if options['checksum'] else options['parallel_checksum'],
        'stop_slave': False if not options['transfer_type'] == 'xtrabackup' else options['stop_slave'],
        'verbose': options['verbose']
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
