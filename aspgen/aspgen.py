#! /usr/bin/env python

from __future__ import division
from __future__ import print_function
from __future__ import with_statement

"""A Secure Password GENerator


"""

import argparse
from decimal import Decimal
from getpass import getpass
from math import log
from pkg_resources import resource_stream
import prettytable
import random
from SecureString import clearmem
import sys

__author__ = 'Alex Hyer'
__email__ = 'theonehyer@gmail.com'
__license__ = 'GPLv3'
__maintainer__ = 'Alex Hyer'
__credits__ = 'Generic Human'
__status__ = 'Alpha'
__version__ = '0.0.1a6'


def basic_stats(password, verbose=False):
    """Detects password composition and produces basic stats

    Args:
        password (str): password to analyze

        verbose (bool): If True, prints progress messages

    Returns:
        int, float: number of password combinations and entropy of password

    Example:
        >>> combinations, entropy = basic_stats('password')
        >>> print(combinations)
        208827064576
        >>> print(entropy)
        37.6035177451
    """

    # Get character sets
    pass_set = set(password)
    lower_letters = set(password_characters(all=False, lower_letters=True))
    upper_letters = set(password_characters(all=False, upper_letters=True))
    special_chars = set(password_characters(all=False, special_chars=True))

    possible_chars = 0

    # Detect characters and combine sets
    if len(pass_set.intersection(lower_letters)) != 0:
        if verbose:
            print('Detected lowercase letters in password')
        possible_chars += len(lower_letters)
    if len(pass_set.intersection(upper_letters)) != 0:
        if verbose:
            print('Detected uppercase letters in password')
        possible_chars += len(upper_letters)
    if len(pass_set.intersection(special_chars)) != 0:
        if verbose:
            print('Detected special characters in password')
        possible_chars += len(special_chars)

    combinations = possible_chars ** len(password)
    entropy = log(combinations, 2)

    return combinations, entropy


def crack_times(combinations, speeds):
    """Calculate average times to crack a password

    Assumes password occurs uniformly across all possible combinations such
    that the probability of a single given password is (1 / combinations).

    Args:
        combinations (int): possible combinations of password

        speeds (list): list of floats or ints where each item is a rate at
            which passwords are being guessed

    Returns:
        list: list of floats where each item is the average time to guess a
            password at the rate given in speeds
    """

    times = [float((combinations/2)/time) for time in speeds]

    return times


def dict_stats(password, dict_words, verbose=False):
    """Analyzes dictionary password and returns statistics

    Args:
        password (str): dictionary password to analyze

        dict_words (list): list of words password may come from

        verbose (bool): If True, print progress messages

    Returns:
        int, float: number of password combinations and entropy of password

    Example:
        >>> from pkg_resources import resource_string
        >>> dict_words = resource_string('aspgen', 'common_words.txt').split()
        >>> combinations, entropy = dict_stats('thecatinthehat', dict_words)
        >>> print_stats(combinations, entropy)
        Password Combinations: 3.20e+21
        Password Entropy: 71.44
    """

    words = infer_spaces(password, dict_words)
    if verbose:
        print('{0} words found in password'.format(str(len(words))))
    combinations = len(dict_words) ** len(words)
    entropy = log(combinations, 2)

    return combinations, entropy


# Credit: Generic Human on StackOverflow: http://stackoverflow.com/questions/
# 8870261/how-to-split-text-without-spaces-into-list-of-words
# I modified the code for readability and minor speed improvements
def infer_spaces(string, words):
    """Infer space locations in a string without spaces

    Args:
        string (str): string to infer spaces of

        words (list): list of str containing all possible words

    Returns:
        list: list of words in string

    Example:
        >>> from pkg_resources import resource_string
        >>> dict_words = resource_string('aspgen', 'common_words.txt').split()
        >>> infer_spaces('thecatinthehat', dict_words)
        ['the', 'cat', 'in', 'the', 'hat']
    """

    def best_match(i):
        """Find best match for first i characters in string

        This function makes numerous naughty assumptions about nonlocal
        variables that only work/are made because this function is inside
        another function.

        Args:
            i (int): position of current letter in string

        Returns:
            int, int: cost and length of match
        """

        candidates = enumerate(reversed(cost[max(0, i - max_length):i]))
        return min((c + word_cost.get(string[i - l - 1:i], 9e999), l + 1)
                   for l, c in candidates)

    # Build cost dict assuming Zipf's law and cost = -math.log(probability)
    words_len = len(words)
    word_cost = dict((word, log((i + 1) * log(words_len)))
                     for i, word in enumerate(words))
    max_length = max(len(i) for i in words)

    # Build the cost array
    cost = [0]
    for i in range(1, len(string) + 1):
        c, l = best_match(i)
        cost.append(c)

    # Backtrack to recover the minimal-cost string
    out = []
    i = len(string)
    while i > 0:
        c, l = best_match(i)
        assert c == cost[i]  # Throw error if values don't match last iter
        out.append(string[i - l:i])
        i -= l

    return [i for i in reversed(out)]


def password_characters(all=True, lower_letters=False, upper_letters=False,
                        special_chars=False):
    """Create a list of possible characters for a password

    Args:
        all (bool): same as setting lower_letters, upper_letters, and
                    special_chars all to True

        lower_letters (bool): add lower-case letters to character list

        upper_letters (bool): add upper-case letters to character list

        special_chars (bool): add special characters to character list

    Returns:
        list: List of str characters for password

    Example:
        >>> password_characters(all=False, special_chars=True)
        [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-',
        '.', ':', ';', '<', '=', '>', '?', '[', '\\', ']', '^', '_', '{', '|',
        '}']
    """

    characters = []

    if lower_letters or all:
        characters += [chr(char) for char in range(97, 123)]

    if upper_letters or all:
        characters += [chr(char) for char in range(65, 91)]

    if special_chars or all:
        characters += [chr(char) for char in range(32, 48)]
        characters += [chr(char) for char in range(58, 65)]
        characters += [chr(char) for char in range(91, 97)]
        characters += [chr(char) for char in range(123, 127)]

    return characters


def print_stats(combinations, entropy):
    """Convenience wrapper to print basic password stats

    Print formatted combination and entropy of password

    Args:
        combinations (int): number of combinations of password

        entropy (float): entropy of password

    Example:
        >>> print_stats(10000, 97.235)
        Passwords Combinations: 1.00e+4
        Password Entropy: 97.24
    """

    print('Password Combinations: {0:.2e}'.format(Decimal(combinations)))
    print('Password Entropy: {0:.2f}'.format(entropy))


def main(args):
    """Main function for aspgen

    Args:
        args (ArgumentParser): argparse ArgumentParser class
    """

    if args.tool == 'generator':

        if args.lower_letters or args.upper_letters or args.special_characters:
            args.all = False

        chars = password_characters(all=args.all,
                                    lower_letters=args.lower_letters,
                                    upper_letters=args.upper_letters,
                                    special_chars=args.special_characters)
        max_char = len(chars) - 1

        # Construct Password
        pass_char = []
        for i in range(0, args.length):
            pass_char.append(chars[random.SystemRandom().randint(0, max_char)])
        password = ''.join(pass_char)

        # Erase each password character from memory
        for i in pass_char:
            clearmem(i)
        message = 'Password: {0}'.format(password)
        print(message)
        clearmem(message)

        if args.stats:
            combinations, entropy = basic_stats(password)
            print_stats(combinations, entropy)

        clearmem(password)

    elif args.tool == 'dict_generator':

        # Raise error if lengths would produce zero words to choose from
        if args.max_length < args.min_length:
            raise ValueError('Max word length is less than min word length')

        dict_words = []
        if args.uncommon:
            with resource_stream('aspgen', 'words.txt') as in_handle:
                for word in in_handle:
                    word = word.strip()
                    if args.min_length <= len(word) <= args.max_length:
                        dict_words.append(word)
        else:
            with resource_stream('aspgen', 'common_words.txt') as in_handle:
                for word in in_handle:
                    word = word.strip()
                    if args.min_length <= len(word) <= args.max_length:
                        dict_words.append(word)

        dict_len = len(dict_words)
        words = []
        for i in range(0, args.length):
            random_number = random.SystemRandom().randint(0, dict_len - 1)
            words.append(dict_words[random_number])
        password = ''.join(words)
        message = 'Words in Password: {0}'.format(' '.join(words))
        print(message)
        clearmem(message)
        if args.length > 1:  # clearmem will delete password if one word
            for word in words:
                clearmem(word)
        message = 'Password: {0}'.format(password)
        print(message)
        clearmem(message)

        if args.stats:
            combinations, entropy = dict_stats(password, dict_words)
            print_stats(combinations, entropy)

        clearmem(password)

    elif args.tool == 'analyzer':

        # TODO: Added cracking speed tables
        # TODO: Added 'secure for [activity]' print

        password = getpass()
        combinations, entropy = basic_stats(password, verbose=True)
        clearmem(password)
        print_stats(combinations, entropy)
        # Cite in docs: 3.5e+8 gizmodo/5966169/the-hardware-hackers-use-to-
        # crack-your-passwords
        #  4.0+12 AntMiner S7
        # 1.0e+14 NSA?
        crack_speeds = crack_times(combinations, [3.4e+8, 4.0e+12, 1.0e+14])

    elif args.tool == 'dict_analyzer':

        # TODO: Added brute-force vs. dict calculator
        # TODO: Added cracking speed tables
        # TODO: Added 'secure for [activity]' print

        # Raise error if lengths would produce zero words to choose from
        if args.max_length < args.min_length:
            raise ValueError('Max word length is less than min word length')

        dict_words = []
        with resource_stream('aspgen', 'common_words.txt') as in_handle:
            for word in in_handle:
                word = word.strip()
                if args.min_length <= len(word) <= args.max_length:
                    dict_words.append(word)

        password = getpass()
        words = infer_spaces(password, dict_words)
        print('Password appears to consist of {0} words'.format(
            str(len(words))))
        if args.safe:
            message = 'Words Found: {0}'.format(' '.join(words))
            print(message)
            clearmem(message)
        if args.length > 1:  # clearmem will delete password if one word
            for word in words:
                clearmem(word)
        combinations, entropy = dict_stats(password, dict_words)
        clearmem(password)
        print_stats(combinations, entropy)
        crack_speeds = crack_times(combinations, [3.4e+8, 4.0e+12, 1.0e+14])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.
                                     RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(title='Tools',
                                       dest='tool')

    analyzer = subparsers.add_parser('analyzer',
                                     help='Analyze a given password')
    analyzer.add_argument('-t', '--detailed',
                          action='store_true',
                          help='produce detailed password stats')

    dict_analyzer = subparsers.add_parser('dict_analyzer',
                                          help='Analyze a dictionary-based '
                                               'password')
    dict_analyzer.add_argument('-m', '--min_length',
                               default=5,
                               type=int,
                               help='minimum length word to use in password')
    dict_analyzer.add_argument('-s', '--safe',
                               action='store_true',
                               help='display words found in password, others '
                                    'can see password and aspgen can\'t '
                                    'delete the password from terminal memory')
    dict_analyzer.add_argument('-t', '--detailed',
                               action='store_true',
                               help='produce detailed password stats')
    dict_analyzer.add_argument('-x', '--max_length',
                               default=999,
                               type=int,
                               help='maximum length word to use in password')

    dict_generator = subparsers.add_parser('dict_generator',
                                           help='Securely generate a '
                                                'dictionary-based password')
    dict_generator.add_argument('-l', '--length',
                                default=6,
                                type=int,
                                help='number of words in password')
    dict_generator.add_argument('-m', '--min_length',
                                default=5,
                                type=int,
                                help='minimum length word to use in password')
    dict_generator.add_argument('-t', '--stats',
                                action='store_true',
                                help='print basic stats on password')
    dict_generator.add_argument('-u', '--uncommon',
                                action='store_true',
                                help='permit uncommon words in password')
    dict_generator.add_argument('-x', '--max_length',
                                default=999,
                                type=int,
                                help='maximum length word to use in password')

    generator = subparsers.add_parser('generator',
                                      help='Securely generate a password')
    generator.add_argument('-a', '--all',
                           default=True,
                           action='store_true',
                           help='permit all characters in password [Default]')
    generator.add_argument('-l', '--length',
                           default=12,
                           type=int,
                           help='length of password')
    generator.add_argument('-n', '--numbers',
                           action='store_true',
                           help='permit numbers in password')
    generator.add_argument('-o', '--lower_letters',
                           action='store_true',
                           help='permit lowercase letters in password')
    generator.add_argument('-p', '--alphanumeric',
                           action='store_true',
                           help='permit all letters and numbers in password, '
                                'same as -l, -n, and -u')
    generator.add_argument('-s', '--special_characters',
                           action='store_true',
                           help='permit special characters in password')
    generator.add_argument('-t', '--stats',
                           action='store_true',
                           help='print basic stats on password')
    generator.add_argument('-u', '--upper_letters',
                           action='store_true',
                           help='permit uppercase letters in password')
    args = parser.parse_args()

    main(args)

    sys.exit(0)
