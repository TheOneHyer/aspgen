#! /usr/bin/env python

from __future__ import print_function

"""A Secure Password GENerator


"""

import argparse
import math
import os
from pkg_resources import resource_stream
import random
import sys
from textwrap import wrap

__author__ = 'Alex Hyer'
__email__ = 'theonehyer@gmail.com'
__license__ = 'GPLv3'
__maintainer__ = 'Alex Hyer'
__status__ = 'Alpha'
__version__ = '0.0.3'


def basic_stats(password, verbose=False):
    """Detects password composition and produces basic stats

    Args:
        password (str): password to analyze

        verbose (bool): If True, outputs progress messages

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
            output('Detected lowercase letters in password')
        possible_chars += len(lower_letters)
    if len(pass_set.intersection(upper_letters)) != 0:
        if verbose:
            output('Detected uppercase letters in password')
        possible_chars += len(upper_letters)
    if len(pass_set.intersection(special_chars)) != 0:
        if verbose:
            output('Detected special characters in password')
        possible_chars += len(special_chars)

    combinations = possible_chars ** len(password)
    entropy = math.log(combinations, 2)

    return combinations, entropy


def dict_stats(words, dict_words):
    """Performs simple calculations for dictionary passwords

    Args:
        words (int): number of words in password

        dict_words (int): number of words in dictionary password was made from

    Returns:
        int, float: number of password combinations and entropy of password
    """

    combinations = dict_words ** words
    entropy = math.log(combinations, 2)

    return combinations, entropy


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


def output(message, width=79):
    """Convenience wrapper, print message wrapping lines longer than width

    Args:
        message (str): message to wrap and print

        width (int): max line length

    Example:
        >>> output('a long line', 79)
        a long line
    """

    print('{0}'.join(wrap(message, width)).format(os.linesep))


def main(args):
    """Main function for aspgen

    Args:
        args (ArgumentParser): argparse ArgumentParser class
    """

    if args.tool == 'generator':

        if args.lower_letters or args.upper_letters or args.special_characters:
            args.all = False

        password = []
        chars = password_characters(all=args.all,
                                    lower_letters=args.lower_letters,
                                    upper_letters=args.upper_letters,
                                    special_chars=args.special_characters)
        max_char = len(chars) - 1

        for i in range(0, args.length):
            password.append(chars[random.SystemRandom().randint(0, max_char)])
        password = ''.join(password)
        password = password.replace('{', '{{')
        password = password.replace('}', '}}')
        output('Password: {0}'.format(password))

        if args.stats:
            combinations, entropy = basic_stats(password)
            output('Password Combinations: {0}'.format(combinations))
            output('Password Entropy: {0}'.format(entropy))

    if args.tool == 'dict_generator':

        # Raise error if lengths would produce zero words to choose from
        if args.max_length < args.min_length:
            raise ValueError('Max word length is less than min word length')

        pass_list = []
        if args.uncommon:
            with resource_stream('aspgen', 'words.txt') as in_handle:
                for word in in_handle:
                    word = word.strip()
                    if args.min_length <= len(word) <= args.max_length:
                        pass_list.append(word)
        else:
            with resource_stream('aspgen', 'common_words.txt') as in_handle:
                for word in in_handle:
                    word = word.strip()
                    if args.min_length <= len(word) <= args.max_length:
                        pass_list.append(word)

        password_words = []
        for i in range(0, args.length):
            random_number = random.SystemRandom().randint(0, len(pass_list)-1)
            password_words.append(pass_list[random_number])
        output('Words in Password: {0}'.format(' '.join(password_words)))
        output('Password: {0}'.format(''.join(password_words)))

        if args.stats:
            combinations, entropy = dict_stats(len(password_words),
                                               len(pass_list))
            output('Password Combinations: {0}'.format(combinations))
            output('Password Entropy: {0}'.format(entropy))

    if args.tool == 'analyzer':
        print('Tool not ready yet')
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.
                                     RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(title='Tools',
                                       dest='tool')

    analyzer = subparsers.add_parser('analyzer',
                                     help='Analyze a given password')

    dict_generator = subparsers.add_parser('dict_generator',
                                           help='Securely generate a '
                                                'dictionary-based password')
    dict_generator.add_argument('-l', '--length',
                                default=6,
                                type=int,
                                help='number of words to construct password')
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
