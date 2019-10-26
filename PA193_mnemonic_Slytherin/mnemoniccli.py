#!/usr/bin/env python3
"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import argparse
import logging
import sys
import typing
import warnings
from binascii import unhexlify, hexlify
from enum import Enum, unique
from pprint import saferepr
from typing import Sequence

from PA193_mnemonic_Slytherin import Entropy, Mnemonic, Seed
from PA193_mnemonic_Slytherin import generate, recover, verify
from PA193_mnemonic_Slytherin.mnemonic import MAX_SEED_PASSWORD_LENGTH

__version__ = '0.1.0'
__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)


@unique
class ExitCode(Enum):
    """
    Return codes.
    Some are inspired by sysexits.h.
    """
    EX_OK = 0
    """Program terminated successfully."""

    UNKNOWN_FAILURE = 1
    """Program terminated due to unknown error."""

    ARGUMENTS = 2
    """Incorrect or missing arguments provided."""

    EX_DATAERR = 65
    """The input data was incorrect in some way."""

    EX_NOINPUT = 66
    """An input file (not a system file) did not exist or was not readable."""

    EX_UNAVAILABLE = 69
    """Required program or file does not exist."""

    EX_NOPERM = 77
    """Permission denied."""

    SEEDS_DO_NOT_MATCH = 125
    """Provided seed and mnemonic phrase (seed generated from mnemonic phrase) do not match."""

    KEYBOARD_INTERRUPT = 130
    """Program received SIGINT."""


class Config(object):
    @unique
    class Format(Enum):
        """Formats for reading and writing entropy and seed."""
        BINARY = 'bin'
        TEXT_HEXADECIMAL = 'hex'

    PROGRAM_NAME = 'mnemoniccli'
    PROGRAM_DESCRIPTION = 'BIP39 Mnemonic Phrase Generator and Verifier'
    LOGGING_LEVELS_DICT = {'debug': logging.DEBUG,
                           'warning': logging.WARNING,
                           'info': logging.INFO,
                           'error': logging.ERROR,
                           'critical': logging.ERROR,
                           'disabled': None,  # logging disabled
                           }
    LOGGING_LEVEL_DEFAULT = 'disabled'

    def __init__(self,
                 logging_level: int,
                 entropy_filepath: str,
                 seed_filepath: str,
                 mnemonic_filepath: str,
                 format_: Format,
                 password: str,
                 generate_: bool,
                 recover_: bool,
                 verify_: bool,
                 ):
        self.logging_level = logging_level
        self.entropy_filepath = entropy_filepath
        self.seed_filepath = seed_filepath
        self.mnemonic_filepath = mnemonic_filepath
        self.format = format_
        self.password = password
        self.generate = generate_
        self.recover = recover_
        self.verify = verify_

    @classmethod
    def init_parser(cls) -> argparse.ArgumentParser:
        """
        Initialize argument parser.
        :rtype: argparse.ArgumentParser
        :return: initialized parser
        """
        def valid_password(password):
            if len(password) > MAX_SEED_PASSWORD_LENGTH:
                raise argparse.ArgumentTypeError("password is longer than {} characters".format(
                    MAX_SEED_PASSWORD_LENGTH))
            return password
        parser = argparse.ArgumentParser(
            prog=cls.PROGRAM_NAME,
            description=cls.PROGRAM_DESCRIPTION,
            epilog='Team Slytherin: @sobuch, @lsolodkova, @mvondracek.\n'
                   'Secure Coding Principles and Practices (PA193)\n'
                   'Faculty of Informatics (FI)\n'
                   'Masaryk University (MU)'
        )
        parser.add_argument('-V', '--version', action='version', version='%(prog)s {}'.format(__version__))
        parser.add_argument('-ll', '--logging-level',
                            # NOTE: The type is called before check against choices. In order to display logging level
                            # names as choices, name to level int value conversion cannot be done here. Conversion is
                            # done after parser call in `self.parse_args`.
                            default=cls.LOGGING_LEVEL_DEFAULT,
                            choices=cls.LOGGING_LEVELS_DICT,
                            help='select logging level (default: %(default)s)'
                            )
        parser.add_argument('-e', '--entropy',
                            help='path to file with entropy, input/output depends on action,',
                            metavar='FILE'
                            )
        parser.add_argument('-s', '--seed',
                            help='path to file with seed, input/output depends on action,',
                            metavar='FILE'
                            )
        parser.add_argument('-m', '--mnemonic',
                            help='path to file with mnemonic, input/output depends on action,',
                            metavar='FILE'
                            )
        parser.add_argument('-f', '--format',
                            default=cls.Format.TEXT_HEXADECIMAL.value,
                            choices={f.value: f for f in cls.Format},
                            help='select input and output format (default: %(default)s)'
                            )
        parser.add_argument('-p', '--password',
                            help='password for protection of seed',
                            default='',
                            type=valid_password
                            )
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-g', '--generate',
                           action='store_true',
                           help='generate seed and mnemonic phrase from entropy'
                           )
        group.add_argument('-r', '--recover',
                           action='store_true',
                           help='recover entropy and seed from mnemonic phrase'
                           )
        group.add_argument('-v', '--verify',
                           action='store_true',
                           help='verify if provided phrase generates expected seed'
                           )
        return parser

    @classmethod
    def parse_args(cls, args: Sequence[str]):
        """Parse command line arguments and store checked and converted values in Config object.

        According to default behaviour of `argparse.ArgumentParser`, this method terminates
        program with exit code 2 (corresponding to `ExitCode.ARGUMENTS`) if passed arguments are
        invalid. If arguments contain -h/--help or -V/--version, program is terminated with exit
        code 0 (corresponding to `ExitCode.E_OK`).
        :type args: Sequence[str]
        :param args: argument strings
        """
        parser = cls.init_parser()  # type: argparse.ArgumentParser
        # NOTE: Call to parse_args with namespace=self does not set logging_level with default value, if argument is not
        # in provided args.
        parsed_args = parser.parse_args(args=args)
        # basic input file path check
        if parsed_args.generate and not parsed_args.entropy:
            parser.error('argument entropy is required with action `generate`'.format(parsed_args.entropy))
        elif parsed_args.recover and not parsed_args.mnemonic:
            parser.error('argument mnemonic is required with action `recover`'.format(parsed_args.entropy))
        elif parsed_args.verify:
            if not parsed_args.mnemonic:
                parser.error('argument mnemonic is required with action `verify`'.format(parsed_args.entropy))
            if not parsed_args.seed:
                parser.error('argument seed is required with action `verify`'.format(parsed_args.entropy))

        config = cls(
            # name to value conversion as noted in `self.init_parser`
            logging_level=cls.LOGGING_LEVELS_DICT[parsed_args.logging_level],
            entropy_filepath=parsed_args.entropy,
            mnemonic_filepath=parsed_args.mnemonic,
            seed_filepath=parsed_args.seed,
            format_=cls.Format(parsed_args.format),
            password=parsed_args.password,
            generate_=parsed_args.generate,
            recover_=parsed_args.recover,
            verify_=parsed_args.verify,
        )
        return config


def cli_entry_point():
    try:
        exit_code = main(sys.argv)
    except KeyboardInterrupt:
        print('Stopping.')
        logger.warning('received KeyboardInterrupt, stopping')
        sys.exit(ExitCode.KEYBOARD_INTERRUPT.value)
    except Exception as e:
        logger.critical(str(e) + ' ' + saferepr(e))
        print(str(e), file=sys.stderr)
        sys.exit(ExitCode.UNKNOWN_FAILURE.value)
    else:
        sys.exit(exit_code.value)


def action_generate(config: Config) -> ExitCode:
    read_mode = 'rb' if config.format is Config.Format.BINARY else 'r'
    write_mode = 'wb' if config.format is Config.Format.BINARY else 'w'
    # TODO Check file size before reading?
    try:
        with open(config.entropy_filepath, read_mode) as file:
            entropy = file.read()  # type: typing.Union[bytes, str]
    except FileNotFoundError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_NOINPUT
    if config.format is Config.Format.TEXT_HEXADECIMAL:
        entropy = unhexlify(entropy)  # type: bytes
    try:
        entropy = Entropy(entropy)
    except ValueError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_DATAERR
    mnemonic, seed = generate(entropy, config.password)
    with open(config.mnemonic_filepath, 'w') as file:
        file.write(mnemonic)
    logger.info('Mnemonic written to {}.'.format(config.mnemonic_filepath))
    with open(config.seed_filepath, write_mode) as file:
        if config.format is Config.Format.TEXT_HEXADECIMAL:
            seed = str(hexlify(seed), 'ascii')
        file.write(seed)
    logger.info('Seed written to {}.'.format(config.seed_filepath))
    print('[DONE] Generate, mnemonic in {}, seed in {}.'.format(config.mnemonic_filepath, config.seed_filepath))
    return ExitCode.EX_OK


def action_recover(config: Config) -> ExitCode:
    read_mode = 'rb' if config.format is Config.Format.BINARY else 'r'
    write_mode = 'wb' if config.format is Config.Format.BINARY else 'w'
    # TODO Check file size before reading?
    try:
        with open(config.mnemonic_filepath, 'r') as file:
            mnemonic = file.read()  # type: str
    except FileNotFoundError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_NOINPUT
    try:
        mnemonic = Mnemonic(mnemonic)
    except ValueError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_DATAERR
    entropy, seed = recover(mnemonic, config.password)
    with open(config.entropy_filepath, write_mode) as file:
        if config.format is Config.Format.TEXT_HEXADECIMAL:
            entropy = str(hexlify(entropy), 'ascii')
        file.write(entropy)
    logger.info('Entropy written to {}.'.format(config.entropy_filepath))
    with open(config.seed_filepath, write_mode) as file:
        if config.format is Config.Format.TEXT_HEXADECIMAL:
            seed = str(hexlify(seed), 'ascii')
        file.write(seed)
    logger.info('Seed written to {}.'.format(config.seed_filepath))
    print('[DONE] Recover, entropy in {}, seed in {}.'.format(config.entropy_filepath, config.seed_filepath))
    return ExitCode.EX_OK


def action_verify(config: Config) -> ExitCode:
    read_mode = 'rb' if config.format is Config.Format.BINARY else 'r'
    write_mode = 'wb' if config.format is Config.Format.BINARY else 'w'
    # TODO Check file size before reading?
    try:
        with open(config.mnemonic_filepath, 'r') as file:
            mnemonic = file.read()  # type: str
    except FileNotFoundError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_NOINPUT
    try:
        mnemonic = Mnemonic(mnemonic)
    except ValueError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_DATAERR
    # TODO Check file size before reading?
    try:
        with open(config.seed_filepath, read_mode) as file:
            seed = file.read()  # type: typing.Union[bytes, str]
    except FileNotFoundError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_NOINPUT
    if config.format is Config.Format.TEXT_HEXADECIMAL:
        seed = unhexlify(seed)  # type: bytes
    try:
        seed = Seed(seed)
    except ValueError as e:
        logger.critical(str(e))
        print(str(e), file=sys.stderr)
        return ExitCode.EX_DATAERR
    match = verify(mnemonic, seed, config.password)
    if not match:
        msg = 'Seeds do not match.'
        logger.info(msg)
        print(msg, file=sys.stderr)
        return ExitCode.SEEDS_DO_NOT_MATCH
    msg = 'Seeds match.'
    logger.info(msg)
    print(msg)
    return ExitCode.EX_OK


def main(argv) -> ExitCode:
    # TODO check for errors related to file IO
    logging.captureWarnings(True)
    warnings.simplefilter('always', ResourceWarning)

    config = Config.parse_args(argv[1:])  # argv[0] is program name
    # On error with parsing argument, program was terminated by `Config.parse_args` with exit code 2 corresponding to
    # `ExitCode.ARGUMENTS`. If arguments contained -h/--help or -V/--version, program was terminated wtih exit code 0,
    # which corresponds to `ExitCode.E_OK`
    if config.logging_level:
        logging.basicConfig(format='%(asctime)s %(name)s[%(process)d] %(levelname)s %(message)s',
                            level=config.logging_level)
    else:
        logging.disable(logging.CRITICAL)
    logger.debug('Config parsed from args.')

    # region # TODO What types of errors/exceptions can happen here?
    exitcode = ExitCode.EX_OK
    if config.generate:
        exitcode = action_generate(config)
    elif config.recover:
        exitcode = action_recover(config)
    elif config.verify:
        exitcode = action_verify(config)
    # endregion

    logger.debug('exit code: {} {}'.format(exitcode.name, exitcode.value))
    return exitcode


if __name__ == '__main__':
    cli_entry_point()
