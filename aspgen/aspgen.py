#! /usr/bin/env python

from __future__ import print_function

"""A Secure Password GENerator


"""

import argparse
from math import log
import os
from pkg_resources import resource_stream
import random
import sys
from textwrap import wrap

__author__ = 'Alex Hyer'
__email__ = 'theonehyer@gmail.com'
__license__ = 'GPLv3'
__maintainer__ = 'Alex Hyer'
__credits__ = 'Generic Human'
__status__ = 'Alpha'
__version__ = '0.0.1a4'


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
    entropy = log(combinations, 2)

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

        pass_len = len(pass_list)
        password_words = []
        for i in range(0, args.length):
            random_number = random.SystemRandom().randint(0, pass_list - 1)
            password_words.append(pass_list[random_number])
        output('Words in Password: {0}'.format(' '.join(password_words)))
        output('Password: {0}'.format(''.join(password_words)))

        if args.stats:
            combinations, entropy = dict_stats(len(password_words), pass_len)
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
