#
# BIP39 Mnemonic Phrase Generator and Verifier
#
# Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
# Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
# Masaryk University (MU)                         https://www.muni.cz/en
#
# Team Slytherin: @sobuch, @lsolodkova, @mvondracek.
#
# 2019
r"""

:Example:

>>> from pa193mnemonicslytherin import Entropy, Mnemonic, Seed, generate, recover, verify
>>> password = 'secret123'
>>> entropy = Entropy(b'\x41' * 16)
>>> mnemonic, seed = generate(entropy, password)
>>>
>>> entropy_recovered, seed_recovered = recover(mnemonic, password)
>>> entropy_recovered == entropy and seed_recovered == seed
True
>>>
>>> verify(mnemonic, seed, password)
True

"""
import hmac
import logging
from contextlib import closing
from copy import deepcopy
from hashlib import sha256, sha512
from typing import List, Tuple, BinaryIO
#from typing import Optional
from unicodedata import normalize

import pkg_resources

__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)

ENGLISH_DICTIONARY_NAME = 'english.lst'
PBKDF2_ROUNDS = 2048
SEED_LEN = 64
MAX_SEED_PASSWORD_LENGTH = 256


def _xor_byte_strings(b1: bytes, b2: bytes) -> bytes:
    """Function for XOR'ing two objects of byte type
    Reference implementation: https://en.wikipedia.org/wiki/XOR_cipher
    :rtype: bytes
    :return b1 XOR b2
    """
    return bytes([x ^ y for x, y in zip(b1, b2)])


def _pbkdf2_sha512(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Password Based Key Derivation Function
    https://en.wikipedia.org/wiki/PBKDF2
    Uses HMAC-SHA512, derived key length is 512 bit
    :rtype: bytes
    :return: key derived by PBKDF2 algorithm
    """
    # The first iteration of PRF uses Password as the PRF key
    # and Salt concatenated with i encoded as a big-endian
    # 32-bit integer as the input.
    u = hmac.new(password, salt + (1).to_bytes(4, byteorder='big'), digestmod=sha512).digest()
    f = u  # f is the xor (^) of c iterations of chained PRFs
    for i in range(1, iterations):
        u = hmac.new(password, u, digestmod=sha512).digest()
        f = _xor_byte_strings(f, u)
    return f


class _DictionaryAccess:
    """Abstract class for classes requiring dictionary access
    """

    def __init__(self, dictionary_name: str = ENGLISH_DICTIONARY_NAME):
        """Load the dictionary.
        Currently uses 1 default dictionary with English words.
        # TODO Should we support multiple dictionaries for various languages?
        :raises FileNotFoundError: If dictionary file with given `dictionary_name` could not be found.
        :raises PermissionError: If dictionary could not be retrieved due to denied permission.  # TODO test this
        :raises ValueError: on invalid dictionary
        :raises UnicodeError: If dictionary contains invalid unicode sequences.
        :rtype: Tuple[List[str], Dict[str, int]]
        :return: List and dictionary of words
        """
        if not isinstance(dictionary_name, str):
            raise TypeError('argument `dictionary_name` should be str, not {}'.format(
                type(dictionary_name).__name__))

        self._dict_list = []
        self._dict_dict = {}

        # > Normally, you should try to use resource_string or resource_stream,
        # > unless you are interfacing with code you don't control (especially
        # > C code) that absolutely must have a filename. The reason is that if
        # > you ask for a filename, and your package is packed into a zipfile,
        # > then the resource must be extracted to a temporary directory, which
        # > is a more costly operation than just returning a string or
        # > file-like object.
        # > http://peak.telecommunity.com/DevCenter/PythonEggs#accessing-package-resources
        # > from https://setuptools.readthedocs.io/en/latest/setuptools.html#accessing-data-files-at-runtime
        dictionary = pkg_resources.resource_stream(__package__, dictionary_name)  # type: BinaryIO
        with closing(dictionary) as f:
            for i in range(2048):
                try:
                    line_bytes = next(f)  # raises StopIteration, caught below
                except StopIteration:
                    raise ValueError('Cannot instantiate dictionary')
                line = line_bytes.decode().strip()  # `line_bytes.decode()` can raise UnicodeError, propagated
                if len(line) > 16 or len(line.split()) != 1:
                    raise ValueError('Cannot instantiate dictionary')
                self._dict_list.append(line)
                self._dict_dict[line] = i
            if f.read():
                raise ValueError('Cannot instantiate dictionary')


class Seed(bytes):
    """Seed representation, validation, and comparison."""

    def __init__(self, seed: bytes) -> None:
        # noinspection PyTypeChecker
        """Initialize Seed representing bytes of seed.

        Performs basic validation.

        :param bytes seed: Seed represented as bytes.
        :raises ValueError: on invalid parameter value
        :raises TypeError: on invalid parameter type

        :Example:

        >>> from pa193mnemonicslytherin import Seed
        >>> Seed(b'\x41' * 64)
        b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        >>> # examples of invalid use
        >>> Seed(b'\x41')
        Traceback (most recent call last):
        ValueError: length of argument `seed` should be 64, not 1
        >>> Seed(123)
        Traceback (most recent call last):
        TypeError: argument `seed` should be bytes, not int

        """
        if not isinstance(seed, bytes):
            raise TypeError('argument `seed` should be bytes, not {}'.format(type(seed).__name__))
        if len(seed) != SEED_LEN:
            raise ValueError('length of argument `seed` should be {}, not {}'.format(SEED_LEN, len(seed)))
        super().__init__()

    def __eq__(self, other: object) -> bool:
        """Compare seeds in constant time to prevent timing attacks.
        :rtype: bool
        :return: True if seeds are equal, False otherwise.

        :Example:

        >>> from pa193mnemonicslytherin import Seed
        >>> s_A_1 = Seed(b'\x41' * 64)
        >>> s_A_2 = Seed(b'\x41' * 64)
        >>> s_b = Seed(b'\x62' * 64)
        >>> s_A_1 == s_A_2
        True
        >>> s_A_1 == s_b
        False

        """
        result = 0
        if not isinstance(other, Seed):
            result = 1
            s = self
        else:
            s = other
        for b1, b2 in zip(self, s):
            result |= b1 ^ b2
        return result == 0

    def __ne__(self, other: object) -> bool:
        """Compare seeds in constant time to prevent timing attacks.
        :rtype: bool
        :return: True if seeds are not equal, False otherwise.

        :Example:

        >>> from pa193mnemonicslytherin import Seed
        >>> s_A_1 = Seed(b'\x41' * 64)
        >>> s_A_2 = Seed(b'\x41' * 64)
        >>> s_b = Seed(b'\x62' * 64)
        >>> s_A_1 != s_A_2
        False
        >>> s_A_1 != s_b
        True

        """
        return not (self == other)


class Entropy(bytes, _DictionaryAccess):
    """Entropy representation, validation, and transformation to Mnemonic."""
    VALID_ENTROPY_BYTE_LENGTHS = (16, 20, 24, 28, 32)

    def __init__(self, entropy: bytes) -> None:
        # noinspection PyTypeChecker
        """Initialize Entropy representing bytes of entropy.

        Checks whether provided bytes represent a valid entropy according to
        `BIP39 <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>`_.

            The mnemonic must encode entropy in a multiple of 32 bits. With
            more entropy security is improved but the sentence length
            increases. We refer to the initial entropy length as ENT.
            The allowed size of ENT is 128-256 bits.

            `BIP39, Generating the mnemonic <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic>`_

        :param bytes entropy: Entropy represented as bytes.
        :raises ValueError: on invalid parameter value
        :raises TypeError: on invalid parameter type

        :Example:

        >>> from pa193mnemonicslytherin import Entropy
        >>> Entropy(b'\x41' * 16)
        b'AAAAAAAAAAAAAAAA'
        >>> # examples of invalid use
        >>> Entropy(b'\x41')
        Traceback (most recent call last):
        ValueError: length of argument `entropy` should be one of (16, 20, 24, 28, 32), not 1
        >>> Entropy(123)
        Traceback (most recent call last):
        TypeError: argument `entropy` should be bytes, not int

        """
        if not isinstance(entropy, bytes):
            raise TypeError('argument `entropy` should be bytes, not {}'.format(type(entropy).__name__))
        if len(entropy) not in self.VALID_ENTROPY_BYTE_LENGTHS:
            raise ValueError('length of argument `entropy` should be one of {}, not {}'.format(
                self.VALID_ENTROPY_BYTE_LENGTHS, len(entropy)))
        super().__init__()
        _DictionaryAccess.__init__(self)
        self.__mnemonic = None  # type: Optional[Mnemonic]

    def checksum(self) -> int:
        """Calculate checksum of this entropy based on its length.

        :rtype: int
        :return: checksum

        :Example:

        >>> from pa193mnemonicslytherin import Entropy
        >>> entropy = Entropy(b'\x41' * 16)
        >>> entropy.checksum()
        9

        """
        entropy_hash = sha256(self).digest()
        assert len(self) % 4 == 0
        checksum_length = len(self) // 4
        return int.from_bytes(entropy_hash, byteorder='big') >> (256 - checksum_length)

    def to_mnemonic(self) -> 'Mnemonic':
        """Convert entropy to mnemonic phrase using dictionary.

        Converted Mnemonic instance is stored and calls to this method always
        return its deep copy.

            Checksum is computed using first ENT/32 bits of SHA256 hash.
            Concatenated bits are split into groups of 11 bits, each encoding
            a number from 0-2047, serving as an index into a wordlist.

            `BIP39, Generating the mnemonic <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic>`_

        :rtype: Mnemonic
        :return: Mnemonic

        :Example:

        >>> from pa193mnemonicslytherin import Entropy
        >>> entropy = Entropy(b'\x41' * 16)
        >>> entropy.to_mnemonic()
        'donor anxiety expect little beef pass agree choice donor anxiety expect lobster'
        >>> m_a = entropy.to_mnemonic()
        >>> m_b = entropy.to_mnemonic()
        >>> m_a == m_b and m_a is not m_b
        True

        """
        if not self.__mnemonic:
            shift = len(self) // 4
            checksum = self.checksum()

            # Concatenated bits representing the indexes
            indexes_bin = (int.from_bytes(self, byteorder='big') << shift) | checksum

            # List of indexes, number of which is MS = (ENT + CS) / 11 == shift * 3
            indexes = [(indexes_bin >> i * 11) & 2047 for i in reversed(range(shift * 3))]

            words = [self._dict_list[i] for i in indexes]
            self.__mnemonic = Mnemonic(' '.join(words))
        return deepcopy(self.__mnemonic)


class Mnemonic(str, _DictionaryAccess):
    """Mnemonic representation, validation, and transformation to Entropy
    or Seed.
    """

    def __init__(self, mnemonic: str):
        # noinspection PyTypeChecker
        """Initialize Mnemonic representing bytes of mnemonic.

        Converts mnemonic phrase to entropy using dictionary to ensure its
        validity.

        :param bytes mnemonic: Mnemonic represented as bytes.
        :raises ValueError: on invalid parameter value
        :raises TypeError: on invalid parameter type

        :Example:

        >>> from pa193mnemonicslytherin import Mnemonic
        >>> Mnemonic('donor anxiety expect little beef pass agree choice donor anxiety expect lobster')
        'donor anxiety expect little beef pass agree choice donor anxiety expect lobster'
        >>> # examples of invalid use
        >>> Mnemonic(123)
        Traceback (most recent call last):
        TypeError: argument `mnemonic` should be str, not int
        >>> Mnemonic('donor')
        Traceback (most recent call last):
        ValueError: argument `mnemonic` has invalid number of words, 1 given, expected one of (12, 15, 18, 21, 24)
        >>> Mnemonic('slytherin ' * 12)
        Traceback (most recent call last):
        ValueError: argument `mnemonic` contains word `slytherin` which is not in current dictionary
        >>> Mnemonic('hello ' * 12)
        Traceback (most recent call last):
        ValueError: argument `mnemonic` includes checksum 6 different from computed 1
        
        """
        if not isinstance(mnemonic, str):
            raise TypeError('argument `mnemonic` should be str, not {}'.format(type(mnemonic).__name__))

        mnemonic.encode('utf-8')  # to check for valid UTF-8
        mnemonic = normalize('NFKD', mnemonic)
        super().__init__()
        _DictionaryAccess.__init__(self)

        words = mnemonic.split()
        n_words = len(words)
        valid_mnemonic_words_numbers = (12, 15, 18, 21, 24)
        if n_words not in valid_mnemonic_words_numbers:
            raise ValueError('argument `mnemonic` has invalid number of words, {} given, expected one of {}'
                             .format(n_words, valid_mnemonic_words_numbers))

        try:
            indexes = [self._dict_dict[word] for word in words]
        except KeyError as e:
            raise ValueError('argument `mnemonic` contains word `{}` which is not in current dictionary'
                             .format(e.args[0])) from e

        # Concatenate indexes into single variable
        indexes_bin = sum([indexes[-i - 1] << i * 11 for i in reversed(range(n_words))])

        # Number of bits entropy is shifted by
        shift = n_words * 11 // 32

        checksum_included = indexes_bin & (pow(2, shift) - 1)
        entropy_bin = indexes_bin >> shift
        entropy = entropy_bin.to_bytes((n_words * 11 - shift) // 8, byteorder='big')

        self.__entropy = Entropy(entropy)
        # Check correctness
        checksum_computed = self.__entropy.checksum()
        if checksum_included != checksum_computed:
            raise ValueError('argument `mnemonic` includes checksum {} different from computed {}'
                             .format(checksum_included, checksum_computed))

    def to_seed(self, seed_password: str = '') -> Seed:
        # noinspection PyTypeChecker
        # noinspection SpellCheckingInspection
        """Generate seed from the mnemonic phrase.

        Seed can be protected by password. If a seed should not be protected,
        the password is treated as `''` (empty string) by default.

        TODO Converted Seed instance is stored and calls to this method always
        return its deep copy.

        :raises ValueError: on invalid parameter value.
            If `seed_password` is longer than 256 characters.
        :raises TypeError: on invalid parameter type
        :rtype: Seed
        :return: Seed

        :Example:

        >>> from binascii import hexlify
        >>> from pa193mnemonicslytherin import Mnemonic
        >>> mnemonic = Mnemonic('donor anxiety expect little beef pass agree choice donor'
        ...                     ' anxiety expect lobster')
        >>> hexlify(mnemonic.to_seed())
        b'd951b58b74507e4e34d4162fbf0193a904572c5e28b4d127f05587a8b39b909cdca65078dacec1e272a22306a67d084c51d8ee50442b6bad1492a5f4b46a1c38'
        >>> s_a = mnemonic.to_seed()
        >>> s_b = mnemonic.to_seed()
        >>> s_a == s_b and s_a is not s_b
        True
        >>> # examples of invalid use
        >>> mnemonic.to_seed(123)
        Traceback (most recent call last):
        TypeError: argument `seed_password` should be str, not int
        >>> mnemonic.to_seed('a' * 257)
        Traceback (most recent call last):
        ValueError: length of argument `seed_password` should be at most 256, not 257
        
        """
        if not isinstance(seed_password, str):
            raise TypeError('argument `seed_password` should be str, not {}'.format(type(seed_password).__name__))
        # the length of the password is bounded to 256
        if len(seed_password) > MAX_SEED_PASSWORD_LENGTH:
            raise ValueError('length of argument `seed_password` should be at most {}, not {}'.format(
                MAX_SEED_PASSWORD_LENGTH, len(seed_password)))
        # the encoding of both inputs should be UTF-8 NFKD
        mnemonic = self.encode('utf-8')
        seed_password = normalize('NFKD', seed_password)
        passphrase = "mnemonic" + seed_password
        passphrase = passphrase.encode('utf-8')
        return Seed(_pbkdf2_sha512(mnemonic, passphrase, PBKDF2_ROUNDS))

    def to_entropy(self) -> Entropy:
        """Generate entropy from the mnemonic phrase.

        Converted Entropy instance is stored and calls to this method always
        return its deep copy.

        :rtype: Entropy
        :return: Entropy

        :Example:

        >>> from pa193mnemonicslytherin import Mnemonic
        >>> mnemonic = Mnemonic('donor anxiety expect little beef pass agree choice donor'
        ...                     ' anxiety expect lobster')
        >>> mnemonic.to_entropy()
        b'AAAAAAAAAAAAAAAA'
        >>> e_a = mnemonic.to_entropy()
        >>> e_b = mnemonic.to_entropy()
        >>> e_a == e_b and e_a is not e_b
        True

        """
        return deepcopy(self.__entropy)


def generate(entropy: Entropy, seed_password: str = '') -> Tuple[Mnemonic, Seed]:
    # noinspection PyTypeChecker
    # noinspection SpellCheckingInspection
    """Generate mnemonic phrase and seed based on provided entropy.

    Seed can be protected by password. If a seed should not be protected,
    the password is treated as `''` (empty string) by default.

    :raises ValueError: on invalid parameter value.
        If `seed_password` is longer than 256 characters.
    :raises TypeError: on invalid parameter type
    :rtype: Tuple[Mnemonic, Seed]
    :return: Two item tuple where first is mnemonic and second is seed.

    :Example:

    >>> from binascii import hexlify
    >>> from pa193mnemonicslytherin import Entropy, generate
    >>> mnemonic, seed = generate(Entropy(b'\x41' * 16))
    >>> mnemonic
    'donor anxiety expect little beef pass agree choice donor anxiety expect lobster'
    >>> hexlify(seed)
    b'd951b58b74507e4e34d4162fbf0193a904572c5e28b4d127f05587a8b39b909cdca65078dacec1e272a22306a67d084c51d8ee50442b6bad1492a5f4b46a1c38'
    >>> mnemonic_pw, seed_pw = generate(Entropy(b'\x41' * 16), 'secret123')
    >>> mnemonic_pw
    'donor anxiety expect little beef pass agree choice donor anxiety expect lobster'
    >>> hexlify(seed_pw)
    b'5fd37e778ba95fdc0fc0fe59d0cdba82471557d44541e49d2a43dc52ae40e40a8fe676b23650610ccc2ed55d55a2db495cce994b777b02cff7f3ffb876f25024'
    >>> mnemonic == mnemonic_pw and seed != seed_pw
    True
    >>> # examples of invalid use
    >>> generate(123, 'secret123')
    Traceback (most recent call last):
    TypeError: argument `entropy` should be of type Entropy, got int
    >>> generate(Entropy(b'\x41' * 16), 123)
    Traceback (most recent call last):
    TypeError: argument `seed_password` should be of type str, got int

    """
    if not isinstance(entropy, Entropy):
        raise TypeError('argument `entropy` should be of type Entropy, got {}'.format(type(entropy).__name__))
    if not isinstance(seed_password, str):
        raise TypeError('argument `seed_password` should be of type str, got {}'.format(type(seed_password).__name__))
    mnemonic = entropy.to_mnemonic()
    seed = mnemonic.to_seed(seed_password)
    return mnemonic, seed


def recover(mnemonic: Mnemonic, seed_password: str = '') -> Tuple[Entropy, Seed]:
    # noinspection PyTypeChecker
    # noinspection SpellCheckingInspection
    """ Recover initial entropy and seed from provided mnemonic phrase.

    Seed can be protected by password. If a seed should not be protected,
    the password is treated as `''` (empty string) by default.

    :raises ValueError: on invalid parameter value.
        If `seed_password` is longer than 256 characters.
    :raises TypeError: on invalid parameter type

    :rtype: Tuple[Entropy, Seed]
    :return: Two item tuple where first is initial entropy and second is seed.

    :Example:

    >>> from binascii import hexlify
    >>> from pa193mnemonicslytherin import Mnemonic, recover
    >>> mnemonic = Mnemonic('donor anxiety expect little beef pass agree choice donor'
    ...                     ' anxiety expect lobster')
    >>> entropy, seed = recover(mnemonic)
    >>> entropy
    b'AAAAAAAAAAAAAAAA'
    >>> hexlify(seed)
    b'd951b58b74507e4e34d4162fbf0193a904572c5e28b4d127f05587a8b39b909cdca65078dacec1e272a22306a67d084c51d8ee50442b6bad1492a5f4b46a1c38'
    >>> entropy_pw, seed_pw = recover(mnemonic, 'secret123')
    >>> entropy_pw
    b'AAAAAAAAAAAAAAAA'
    >>> hexlify(seed_pw)
    b'5fd37e778ba95fdc0fc0fe59d0cdba82471557d44541e49d2a43dc52ae40e40a8fe676b23650610ccc2ed55d55a2db495cce994b777b02cff7f3ffb876f25024'
    >>> entropy == entropy_pw and seed != seed_pw
    True
    >>> # examples of invalid use
    >>> recover(123, 'secret123')
    Traceback (most recent call last):
    TypeError: argument `mnemonic` should be of type Mnemonic, got int
    >>> recover(mnemonic, 123)
    Traceback (most recent call last):
    TypeError: argument `seed_password` should be of type str, got int

    """
    if not isinstance(mnemonic, Mnemonic):
        raise TypeError('argument `mnemonic` should be of type Mnemonic, got {}'.format(type(mnemonic).__name__))
    if not isinstance(seed_password, str):
        raise TypeError('argument `seed_password` should be of type str, got {}'.format(type(seed_password).__name__))

    entropy = mnemonic.to_entropy()
    seed = mnemonic.to_seed(seed_password)
    return entropy, seed


def verify(mnemonic: Mnemonic, expected_seed: Seed, seed_password: str = '') -> bool:
    # noinspection PyTypeChecker
    # noinspection SpellCheckingInspection
    """Verify whether mnemonic phrase matches with expected seed.

    Seed can be protected by password. If a seed should not be protected,
    the password is treated as `''` (empty string) by default.

    :raises ValueError: on invalid parameter value.
        If `seed_password` is longer than 256 characters.

    :raises TypeError: on invalid parameter type

    :rtype: bool
    :return: True if provided phrase generates expected seed, False otherwise.

    :Example:

    >>> from binascii import unhexlify
    >>> from pa193mnemonicslytherin import Mnemonic, Seed, verify
    >>> mnemonic = Mnemonic('donor anxiety expect little beef pass agree choice donor'
    ...                     ' anxiety expect lobster')
    >>> seed = Seed(unhexlify(b'd951b58b74507e4e34d4162fbf0193a904572c5e28b4d127f05587'
    ...                       b'a8b39b909cdca65078dacec1e272a22306a67d084c51d8ee50442b'
    ...                       b'6bad1492a5f4b46a1c38'))
    >>> verify(mnemonic, seed)
    True
    >>> verify(mnemonic, mnemonic.to_seed())
    True
    >>> password = 'secret123'
    >>> seed_pw = mnemonic.to_seed(password)
    >>> verify(mnemonic, seed_pw, password)
    True
    >>> verify(mnemonic, Seed(b'\x41' * 64))
    False
    >>> # examples of invalid use
    >>> verify(mnemonic, 123)
    Traceback (most recent call last):
    TypeError: argument `expected_seed` should be of type Seed, got int
    >>> verify(123, Seed(b'\x41' * 64))
    Traceback (most recent call last):
    TypeError: argument `mnemonic` should be of type Mnemonic, got int
    >>> verify(mnemonic, Seed(b'\x41' * 64), 123)
    Traceback (most recent call last):
    TypeError: argument `seed_password` should be of type str, got int

    """
    if not isinstance(expected_seed, Seed):
        raise TypeError('argument `expected_seed` should be of type Seed, got {}'.format(type(expected_seed).__name__))
    if not isinstance(mnemonic, Mnemonic):
        raise TypeError('argument `mnemonic` should be of type Mnemonic, got {}'.format(type(mnemonic).__name__))
    if not isinstance(seed_password, str):
        raise TypeError('argument `seed_password` should be of type str, got {}'.format(type(seed_password).__name__))

    generated_seed = mnemonic.to_seed(seed_password)
    return expected_seed == generated_seed
