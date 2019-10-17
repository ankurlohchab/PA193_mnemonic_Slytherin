"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import os
import subprocess
import unittest
from tempfile import TemporaryDirectory

from PA193_mnemonic_Slytherin.mnemoniccli import ExitCode


class TestMain(unittest.TestCase):
    """Integration tests for CLI tool."""
    TIMEOUT = 5  # seconds until we terminate the program
    PYTHON = 'python'
    SCRIPT = 'mnemoniccli.py'
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

    def assert_argument_error(self, args):
        cli = subprocess.run(args, timeout=self.TIMEOUT, cwd=self.SCRIPT_DIR,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual('', cli.stdout)
        self.assertNotEqual('', cli.stderr)
        self.assertEqual(ExitCode.ARGUMENTS.value, cli.returncode)

    def assert_argument_ok_terminated(self, args):
        cli = subprocess.run(args, timeout=self.TIMEOUT, cwd=self.SCRIPT_DIR,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertNotEqual('', cli.stdout)
        self.assertEqual('', cli.stderr)
        self.assertEqual(ExitCode.EX_OK.value, cli.returncode)

    def test_arguments_error(self):
        """invalid arguments"""
        self.assert_argument_error([self.PYTHON, self.SCRIPT])
        self.assert_argument_error([self.PYTHON, self.SCRIPT, '-ll', 'FOO'])
        self.assert_argument_error([self.PYTHON, self.SCRIPT, '-g'])
        self.assert_argument_error([self.PYTHON, self.SCRIPT, '-r'])
        self.assert_argument_error([self.PYTHON, self.SCRIPT, '-v'])
        self.assert_argument_error([self.PYTHON, self.SCRIPT, '-g', '-r', '-v'])

    def test_arguments_ok_terminated(self):
        """correct argument resulting in termination"""
        self.assert_argument_ok_terminated([self.PYTHON, self.SCRIPT, '-h'])
        self.assert_argument_ok_terminated([self.PYTHON, self.SCRIPT, '--help'])
        self.assert_argument_ok_terminated([self.PYTHON, self.SCRIPT, '-V'])
        self.assert_argument_ok_terminated([self.PYTHON, self.SCRIPT, '--version'])

    def test_arguments_error_file_path(self):
        """input files don't exist"""
        with TemporaryDirectory() as tmpdir:
            non_existing_filepath = os.path.join(tmpdir, '__this_file_does_not_exist__')
            self.assert_argument_error([self.PYTHON, self.SCRIPT, '-g', '-e', non_existing_filepath])
            self.assert_argument_error([self.PYTHON, self.SCRIPT, '-r', '-m', non_existing_filepath])
            self.assert_argument_error([self.PYTHON, self.SCRIPT, '-v', '-m', non_existing_filepath, '-s', non_existing_filepath])

            with open(os.path.join(tmpdir, '__this_file_exists__.txt'), 'w') as f:
                f.write('foo bar')
            self.assert_argument_error([self.PYTHON, self.SCRIPT, '-v', '-m', f.name, '-s', non_existing_filepath])
            self.assert_argument_error([self.PYTHON, self.SCRIPT, '-v', '-m', non_existing_filepath, '-s', f.name])

    def test_invalid_entropy(self):
        """Invalid input file with entropy
        > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is improved but
        > the sentence length increases. We refer to the initial entropy length as ENT. The allowed size of ENT
        > is 128-256 bits.
        > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
        """
        with TemporaryDirectory() as tmpdir:
            # binary input file
            # basic byte of entropy for this test
            entropy_byte = b'\x01'
            valid_entropy_bytes_lengths = list(range(16, 32 + 1, 4))
            for entropy_bytes_length in range(0, 40):
                if entropy_bytes_length in valid_entropy_bytes_lengths:
                    continue
                with self.subTest(entropy_bytes_length=entropy_bytes_length):
                    with open(os.path.join(tmpdir, '__entropy_binary__.dat'), 'wb') as f:
                        f.write(entropy_byte * entropy_bytes_length)
                    cli = subprocess.run([self.PYTHON, self.SCRIPT, '-g', '-e', f.name, '--format', 'bin'],
                                         timeout=self.TIMEOUT, cwd=self.SCRIPT_DIR,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                    self.assertEqual('', cli.stdout)
                    self.assertEqual('invalid entropy\n', cli.stderr)
                    self.assertEqual(ExitCode.EX_DATAERR.value, cli.returncode)


if __name__ == '__main__':
    unittest.main()
