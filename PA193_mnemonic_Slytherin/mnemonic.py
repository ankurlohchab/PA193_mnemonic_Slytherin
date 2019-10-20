"""
BIP39 Mnemonic Phrase Generator and Verifier

Secure Coding Principles and Practices (PA193)  https://is.muni.cz/course/fi/autumn2019/PA193?lang=en
Faculty of Informatics (FI)                     https://www.fi.muni.cz/index.html.en
Masaryk University (MU)                         https://www.muni.cz/en

Team Slytherin: @sobuch, @lsolodkova, @mvondracek.

2019
"""
import hmac
import logging
import os
from hashlib import pbkdf2_hmac, sha256
from typing import Dict, List, Tuple

__author__ = 'Team Slytherin: @sobuch, @lsolodkova, @mvondracek.'

logger = logging.getLogger(__name__)


ENGLISH_DICTIONARY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'english.txt')
PBKDF2_ROUNDS = 2048
SEED_LEN = 64


class dictionaryAccess:
    """Abstract class for classes requiring dictionary access
    """
    
    def __init__(self):
        # TODO: functions __entropy2mnemonic, __mnemonic2entropy, __is_valid_mnemonic work with dictionary, we could use single
        #       object with this dictionary to prevent multiple file opening and reading and to support multiple dictionaries
        #       for various languages.
        """Load the dictionary.
        Currently uses 1 default dictionary with English words.
        # TODO Should we support multiple dictionaries for various languages?
        :raises FileNotFoundError: on missing file
        :raises ValueError: on invalid dictionary
        :rtype: Tuple[List[str], Dict[str, int]]
        :return: List and dictionary of words
        """
        self.__dict_list = []
        with open(file_path, 'r') as f:
            for i in range(2048):
                self.__dict_list.append(next(f).strip())
                if len(self.__dict_list[-1]) > 16 or len(self.__dict_list[-1].split()) != 1:
                    raise ValueError('invalid dictionary')
            try:
                next(f)
            except StopIteration:
                pass
            else:
                raise ValueError('invalid dictionary')

        self.__dict_dict = {self.__dict_list[i]: i for i in range(len(self.__dict_list))}


class Seed(bytes):
    """Class for seed representation.
    """
    
    def __init__(self, seed: bytes):
        """Check whether provided bytes represent a valid seed.
        :raises ValueError: on invalid parameters
        """
        if not isinstance(seed, bytes) or len(seed) != SEED_LEN:
            raise ValueError('Cannot instantiate seed')
        self.__repr__ = seed


    def __eq__(self, other: object) -> bool:
        """Compare seeds in constant time to prevent timing attacks.
        :rtype: bool
        :return: True if seeds are the same, False otherwise.
        """
        # > hmac.compare_digest` uses an approach designed to prevent timing
        # > analysis by avoiding content-based short circuiting behaviour, making
        #  > it appropriate for cryptography
        # > https://docs.python.org/3.7/library/hmac.html#hmac.compare_digest
        #
        # > Note: If a and b are of different lengths, or if an error occurs,
        # > a timing attack could theoretically reveal information about the types
        #  > and lengths of a and b—but not their values.
        #
        # Type and length of seeds is known to the attacker, but not the value of expected seed.
        if not isinstance(other, Seed):
            return NotImplemented
        return hmac.compare_digest(self, other)


    def __ne__(self, other: object) -> bool:
        """Compare seeds in constant time to prevent timing attacks.
        :rtype: bool
        :return: False if seeds are the same, True otherwise.
        """
        return not (self == other)


class Entropy(bytes, dictionaryAccess):
    """Class for entropy representation.
    """

    def __init__(self, entropy: bytes):
        """Check whether provided bytes represent a valid entropy according to BIP39.
        https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

        > The mnemonic must encode entropy in a multiple of 32 bits. With more entropy security is
        > improved but the sentence length increases. We refer to the initial entropy length as ENT.
        > The allowed size of ENT is 128-256 bits.
        > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
        :raises ValueError: on invalid parameters
        """
        if len(entropy) not in list(range(16, 32+1, 4)):
            raise ValueError('Cannot instantiate entropy')
        self.__repr__ = entropy


    def checksum(self, length: int) -> int:
        """Calculate entropy checksum of set length
        :rtype: int
        :return: checksum
        """
        entropy_hash = sha256(self).digest()
        return int.from_bytes(entropy_hash, byteorder='big') >> 256 - length


    def toMnemonic(self) -> 'Mnemonic':
        """Convert entropy to mnemonic phrase using dictionary.
        :rtype: Mnemonic
        :return: Mnemonic phrase

        > https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#generating-the-mnemonic
        'Checksum is computed using first ENT/32 bits of SHA256 hash. Concatenated bits are split
        into groups of 11 bits, each encoding a number from 0-2047, serving as an index into a
        wordlist.'
        """
        shift = len(self) // 4
        checksum = self.checksum(shift)

        # Concatenated bits representing the indexes
        indexes_bin = (int.from_bytes(self, byteorder='big') << shift) | checksum

        # List of indexes, number of which is MS = (ENT + CS) / 11 == shift * 3
        indexes = [(indexes_bin >> i * 11) & 2047 for i in reversed(range(shift * 3))]

        words = [self.__dict_list[i] for i in indexes]
        return Mnemonic(' '.join(words))


class Mnemonic(str, dictionaryAccess):
    """Class for mnemonic representation.
    """
    
    def __init__(self, mnemonic: str):
        """Convert mnemonic phrase to entropy using dictionary to ensure its validity.
        :raises ValueError: on invalid parameters
        """
        if not isinstance(mnemonic, str):
            raise ValueError('Cannot instantiate mnemonic')
    
        words = mnemonic.split()
        l = len(words)
        if not l in (12, 15, 18, 21, 24):
            raise ValueError('Cannot instantiate mnemonic')

        try:
            indexes = [self.__dict_dict[word] for word in words]
        except KeyError:
            raise ValueError('Cannot instantiate mnemonic')

        # Concatenate indexes into single 
        indexes_bin = sum([indexes[-i - 1] << i * 11 for i in reversed(range(l))])

        # Number of bits entropy is shifted by
        shift = l * 11 // 32

        checksum = indexes_bin & (pow(2, shift) - 1)
        entropy_bin =  indexes_bin >> shift
        entropy = entropy_bin.to_bytes((l * 11 - shift) // 8, byteorder='big')
    
        self.__entropy = Entropy(entropy)
        # Check correctness
        if checksum != self.__entropy.checksum(shift):
            raise ValueError('Cannot instantiate mnemonic')
        
        self.__repr__ = mnemonic


    def toSeed(self, seed_password: str = '') -> Seed:
        """Generate seed from the mnemonic phrase.
        Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
        (empty string) by default.
        :rtype: Seed
        :return: Seed
        """
        # the encoding of both inputs should be UTF-8 NFKD
        mnemonic = self.encode()  # encoding string into bytes, UTF-8 by default
        passphrase = "mnemonic" + seed_password
        passphrase = passphrase.encode()
        return Seed(pbkdf2_hmac('sha512', mnemonic, passphrase, PBKDF2_ROUNDS, SEED_LEN))


    def toEntropy(self) -> Entropy:
        """Generate entropy from the mnemonic phrase.
        :rtype: Entropy
        :return: entropy
        """
        return self.__entropy


def generate(entropy: Entropy, seed_password: str = '') -> Tuple[Mnemonic, Seed]:
    """Generate mnemonic phrase and seed based on provided entropy.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: Tuple[Mnemonic, Seed]
    :return: Two item tuple where first is mnemonic phrase and second is seed.
    """
    mnemonic = entropy.toMnemonic()
    seed = mnemonic.toSeed(seed_password)
    return mnemonic, seed


def recover(mnemonic: Mnemonic, seed_password: str = '') -> Tuple[Entropy, Seed]:
    """ Recover initial entropy and seed from provided mnemonic phrase.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: Tuple[Entropy, Seed]
    :return: Two item tuple where first is initial entropy and second is seed.
    """
    entropy = mnemonic.toEntropy()
    seed = mnemonic.toSeed(seed_password)
    return entropy, seed


def verify(mnemonic: Mnemonic, expected_seed: Seed, seed_password: str = '') -> bool:
    """Verify whether mnemonic phrase matches with expected seed.
    Seed can be protected by password. If a seed should not be protected, the password is treated as `''`
    (empty string) by default.
    :raises ValueError: on invalid parameters
    :rtype: bool
    :return: True if provided phrase generates expected seed, False otherwise.
    """
    generated_seed = mnemonic.toSeed(seed_password)
    return expected_seed == generated_seed


def do_some_work(param: int) -> bool:
    """Placeholder for initial code structure.
    :rtype: bool
    :return True if some work was successful, False otherwise.
    # TODO remove this placeholder as soon as we have some real tests.
    """
    return param == 1
