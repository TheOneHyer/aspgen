#! /usr/bin/env python

from __future__ import division
from __future__ import print_function
from __future__ import with_statement

"""A Secure Password GENerator


"""

import argparse
from getpass import getpass
from math import log
import os
from pkg_resources import resource_stream
from prettytable import PrettyTable
import random
import re
from SecureString import clearmem
#import cStringIO
import sys
import textwrap

__author__ = 'Alex Hyer'
__email__ = 'theonehyer@gmail.com'
__license__ = 'GPLv3'
__maintainer__ = 'Alex Hyer'
__credits__ = 'Generic Human'
__status__ = 'Beta'
__version__ = '0.0.1b4'


def generate_password(chars, length, get_parts=False, secure=True):
    """Generate a string by randomly concatenating strings from a list

    Args:
        chars (list): list of str to generate password from

        length (int): length of password

        get_parts (bool): return strings password is made from, these strings
                          will not be deleted by secure flag

        secure (bool): delete strings in character list from memory after
                       generating password. WARNING: will yield individual
                       strings inaccessible, e.g. if one string is 'a'
                       and secure is enabled, the rest of the program
                       calling this function cannot access the char 'a'
                       anymore. Also, the actual password will remain in
                       memory, only chars are deleted.

    Returns:
        tuple: (password (str), parts (list)), password and strings
               constituting passwords. parts in tuple is None if get_parts
               flag is False

    Example:
        Note: Will not pass docstring test

        >>> generate_password(['a', 'b', 'c'], 5)
        ('abcba', None)
    """

    max_char = len(chars) - 1

    # Construct Password
    parts = []
    for i in range(0, length):
        parts.append(chars[random.SystemRandom().randint(0, max_char)])
    password = ''.join(parts)

    # Erase each password character from memory if not part of password
    if secure is True:
        for i in chars:
            if get_parts is False or i not in parts:
                # Don't clear only part because it clears password
                if length == 1 and i in parts:
                    continue
                clearmem(i)

    if get_parts is False:
        parts = None

    return password, parts


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


def par(message, to_print=False, report=None):
    """Print And Report, convenience wrapper for printing to screen and file

    Args:
        message (str): message to print or write

        to_print (bool): Whether or not to print message to screen

        report (File): file handle to write output to
    """

    if report is not None:
        report.write(message)
    if to_print is True:
        if message.endswith(os.linesep):
            message = re.sub(os.linesep + '$', '', message)
        print(message)


def password_characters(all=True, lower_letters=False, upper_letters=False,
                        numbers=False, special_chars=False):
    """Create a list of possible characters for a password

    Args:
        all (bool): same as setting lower_letters, upper_letters, and
                    special_chars all to True

        lower_letters (bool): add lower-case letters to character list

        upper_letters (bool): add upper-case letters to character list

        numbers (bool): add numbers to character list

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

    if numbers or all:
        characters += [chr(char) for char in range(48, 58)]

    if special_chars or all:
        characters += [chr(char) for char in range(32, 48)]
        characters += [chr(char) for char in range(58, 65)]
        characters += [chr(char) for char in range(91, 97)]
        characters += [chr(char) for char in range(123, 127)]

    return characters


def password_stats(dict_pass=None, dictionary=None,
                   guess_speeds=None, num_parts=None, pass_len=None,
                   verbose=False):
    """Analyze various password statistics

    This function aims to calculate various password statistics as safely as
    possible. This means that it uses as little information as possible to
    perform statistics, aka attempting to avoid needing the actual password
    to perform password statistics. As such, this function takes the number
    of possible characters and length of password rather than the actual
    password. That being said, some advanced dictionary password statistics
    require the actual password. If analyzing a dictionary password,
    the function will attempt to minimize its knowledge of the password during
    analysis. The minimum knowledge necessary to calculate stats is
    determined internally to prevent developers from accidentally asking
    this function to populate memory with more information than necessary.
    If arguments violate minimum information thresholds, this function raises
    assertion errors, i.e. aggressively enforces security.

    Important Notes on Functionality:

    1. If num_parts is None, pass_len is None, and dict_pass is provided,
       dictionary is required. When these combination of arguments are
       satisfied, password_stats uses Zipf's Law to tease apart the words in
       the password and thus determine password length. In order to do this,
       the dictionary must be sorted from the greatest usage frequency in
       the given language to lowest word frequency. If a frequency-sorted
       dictionary is unavailable, this functionality is useless and will
       provide incorrect results. Note: This functionality is inherently
       less secure as it populates memory with the password's components and
       should only be used if a program receives a dictionary password from
       a user. If a program creates the password, provide the number of
       words as pass_len and length of the dictionary used to generate the
       password as num_parts to improve security.

    2. If a dictionary password is provided, password_stats compares the
       entropy of the password as generated from a dictionary versus being
       generated from individual characters to determine the lowest entropy
       of the password. This functionality only works with ASCII and will be
       skipped if using non-ASCII characters; using non-ASCII characters thus
       eliminates the ability of password_stats to determine the lowest
       password entropy.

    3. All password statistics assume password consists of concatenated random
       parts where all random parts have an equal chance of being picked and
       can be picked multiple times, i.e. parts are uniformly distributed and
       selected with replacement.

    Args:
        dict_pass (str): password if dictionary password, else None

        dictionary (list): dictionary used to construct password. Only
                           permitted and required if pass_len is None and
                           dict_pass is provided. Must be sorted by relative
                           frequency of word use in language.

        guess_speeds (list): list of ints representing the guesses/sec a hacker
                             can perform when attempting to crack the
                             password, else None. Returns a table.

        num_parts (int): number of characters and/or words password may be
                         comprised from

        pass_len (int): length of password. Always required unless using a
                        dictionary password where developer wants
                        password_stats to guess the password length.
                        Providing pass_len is more secure and accurate than
                        permitting password_stats to guess length.

        verbose (bool): If True, prints progress messages

    Returns:
        dict: dictionary of password stats. All password stats not calculated
              have value of None. Dictionary keys are (in YAML format):

              combinations <int of password combinations>
              entropy <float of password entropy>
              combinations_raw <if dict_pass is provided, int of password
                                combinations if password generated from ASCII
                                characters>
              entropy_raw <if dict_pass is provided, float of password
                           entropy if password generated from ASCII
                           characters>
              words <if dict_pass and dictionary provided, list of str
                     containing words in password>
              guess_table <if guess_speeds provided, PrettyTable of password
                           guessing speeds>
    """

    # Assert only necessary and sufficient information is given
    if dict_pass is not None:
        try:
            assert dictionary is not None
        except AssertionError:
            raise AssertionError('Must assign "dictionary" with "dict_pass"')

    if dictionary is not None:
        try:
            assert dict_pass is not None
        except AssertionError:
            AssertionError('Must assign "dict_pass" with "dictionary"')
        try:
            assert num_parts is None
        except AssertionError:
            raise AssertionError('Cannot give "num_parts" with "dictionary"')
        try:
            assert pass_len is None
        except AssertionError:
            raise AssertionError('Cannot give "pass_len" with "dictionary"')

    if num_parts is not None:
        try:
            assert pass_len is not None
        except AssertionError:
            raise AssertionError('Must assign "pass_len" with "num_parts"')

    if pass_len is not None:
        try:
            assert num_parts is not None
        except AssertionError:
            raise AssertionError('Must assign "num_parts" with "pass_len"')

    output = {
        'combinations': None,
        'entropy': None,
        'combinations_raw': None,
        'entropy_raw': None,
        'words': None,
        'guess_table': None
    }

    # Set flags to control function flow
    calc_simple_stats = False
    if pass_len is not None and pass_len is not None:
        calc_simple_stats = True

    calc_dict_stats = False
    if dict_pass is not None and dictionary is not None:
        calc_dict_stats = True

    calc_crack_table = False
    if guess_speeds is not None:
        calc_crack_table = True

    if calc_simple_stats is True:
        if verbose is True:
            print('Calculating basic password stats')
        output['combinations'] = num_parts ** pass_len
        output['entropy'] = log(output['combinations'], 2)

    if calc_dict_stats is True:
        if verbose is True:
            print('Calculating dictionary statistics')
            print('Inferring words comprising password')
        output['words'] = infer_spaces(dict_pass, dictionary)
        output['combinations'] = len(dictionary) ** len(output['words'])
        output['entropy'] = log(output['combinations'], 2)
        if verbose is True:
            print('Words in Password: {0}'.format(' '.join(output['words'])))

        if verbose is True:
            print('Determining characters in password')

        # Generate password sets for analysis
        lower_letters = password_characters(all=False, lower_letters=True)
        upper_letters = password_characters(all=False, upper_letters=True)
        numbers = password_characters(all=False, numbers=True)
        special_chars = password_characters(all=False, special_chars=True)
        pass_set = set(dict_pass)

        # Detect characters in password
        num_parts = 0
        if len(pass_set.intersection(lower_letters)) != 0:
            if verbose is True:
                print('Detected lowercase letters in password')
            num_parts += len(lower_letters)
        if len(pass_set.intersection(upper_letters)) != 0:
            if verbose is True:
                print('Detected uppercase letters in password')
            num_parts += len(upper_letters)
        if len(pass_set.intersection(numbers)) != 0:
            if verbose is True:
                print('Detected numbers in password')
            num_parts += len(numbers)
        if len(pass_set.intersection(special_chars)) != 0:
            if verbose is True:
                print('Detected special characters in password')
            num_parts += len(special_chars)

        if verbose:
            print('Calculating basic stats for dictionary password')
        pass_len = len(dict_pass)
        output['combinations_raw'] = num_parts ** pass_len
        output['entropy_raw'] = log(output['combinations_raw'], 2)

    if calc_crack_table is True:
        times = [float(output['combinations'] / 2 / speed)
                 for speed in guess_speeds]
        times = ['{0:.2e}'.format(time) for time in times]
        times.insert(0, 'Time to Guess (sec)')
        guess_speeds = ['{0:.2e}'.format(speed) for speed in guess_speeds]
        guess_speeds.insert(0, 'Guess Speeds (passwords/sec)')
        table = PrettyTable(guess_speeds)
        table.add_row(times)
        output['guess_table'] = table

    return output


def print_stats(combinations, entropy):
    """Convenience wrapper to print basic password stats

    Return formatted combination and entropy of password

    Args:
        combinations (int): number of combinations of password

        entropy (float): entropy of password

    Returns:
        tuple: two strings holding formatted output

    Example:
        >>> a, b = print_stats(10000, 97.235)
        >>> print(a)
        Passwords Combinations: 1.00e+4
        >>> print(b)
        Password Entropy: 97.24
    """

    comb = 'Password Combinations: {0:.2e}'.format(combinations)
    ent = 'Password Entropy: {0:.2f}'.format(entropy)

    return comb, ent


def main(args):
    """Control program flow based on arguments

    Args:
        args (ArgumentParser): argparse ArgumentParser class
    """

    if args.tool == 'generator' or args.tool == 'analyzer':

        if args.tool == 'generator':

            if args.lower_letters is True or args.upper_letters is True or \
                    args.special_characters is True or args.numbers is True:
                args.all = False

            if args.alphanumeric is True:
                args.all = False
                args.lower_letters = True
                args.upper_letters = True
                args.numbers = True
                args.special_characters = False

            chars = password_characters(all=args.all,
                                        lower_letters=args.lower_letters,
                                        upper_letters=args.upper_letters,
                                        numbers=args.numbers,
                                        special_chars=args.special_characters)
            num_chars = len(chars)

            password = generate_password(chars, args.length, secure=False)[0]

            message = 'Password: {0}'.format(password)
            par(message + os.linesep, to_print=True, report=args.report)
            clearmem(message)
            par(os.linesep, report=args.report)

        elif args.tool == 'analyzer':

            password = getpass()
            par('Password: ' + password, report=args.report)
            par(os.linesep, report=args.report)
            par(os.linesep, report=args.report)

            # Generate password sets for analysis
            lower_letters = password_characters(all=False, lower_letters=True)
            upper_letters = password_characters(all=False, upper_letters=True)
            numbers = password_characters(all=False, numbers=True)
            special_chars = password_characters(all=False, special_chars=True)
            pass_set = set(password)

            # Detect characters in password
            num_chars = 0
            if len(pass_set.intersection(lower_letters)) != 0:
                par('Detected lowercase letters in password' + os.linesep,
                    report=args.report)
                num_chars += len(lower_letters)
            if len(pass_set.intersection(upper_letters)) != 0:
                par('Detected uppercase letters in password' + os.linesep,
                    report=args.report)
                num_chars += len(upper_letters)
            if len(pass_set.intersection(numbers)) != 0:
                par('Detected numbers in password' + os.linesep,
                    report=args.report)
                num_chars += len(numbers)
            if len(pass_set.intersection(special_chars)) != 0:
                par('Detected special characters in password' + os.linesep,
                    report=args.report)
                num_chars += len(special_chars)
            par(os.linesep, report=args.report)

        # Analyze password and present stats
        if args.tool == 'analyzer' or args.stats is True:
            par('Password Stats' + os.linesep, report=args.report)
            par('--------------' + os.linesep, report=args.report)
            par(os.linesep, report=args.report)
            stats = password_stats(pass_len=len(password),
                                   num_parts=num_chars,
                                   guess_speeds=args.guess_speeds,
                                   verbose=args.secure)
            c, e = print_stats(stats['combinations'], stats['entropy'])
            par(c + os.linesep, to_print=True, report=args.report)
            par(e + os.linesep, to_print=True, report=args.report)
            if stats['guess_table'] is not None:
                par('{0}Average Time to Cracked Password'.format(os.linesep)
                    + os.linesep, to_print=True, report=args.report)
                par(str(stats['guess_table']), to_print=True,
                    report=args.report)
                par(os.linesep, report=args.report)

            par(os.linesep, report=args.report)

        clearmem(password)

    elif args.tool == 'dict_analyzer' or args.tool == 'dict_generator':

        if args.tool == 'dict_generator':

            # Raise error if lengths would produce zero words to choose from
            if args.max_length < args.min_length:
                raise ValueError('Max word length is less than min word '
                                 'length')

            dict_words = []
            if args.uncommon is True:
                with resource_stream('aspgen', 'words.txt') as in_handle:
                    for word in in_handle:
                        word = word.strip()
                        if args.min_length <= len(word) <= args.max_length:
                            dict_words.append(word)
            else:
                with resource_stream('aspgen', 'common_words.txt') as \
                        in_handle:
                    for word in in_handle:
                        word = word.strip()
                        if args.min_length <= len(word) <= args.max_length:
                            dict_words.append(word)

            password, words = generate_password(dict_words, args.length,
                                                get_parts=True)

            message = 'Words in Password: {0}'.format(' '.join(words))
            par(message + os.linesep, to_print=True, report=args.report)
            clearmem(message)
            if args.length > 1:  # clearmem will clear password if one word
                for word in words:
                    clearmem(word)

            message = 'Password: {0}'.format(password)
            par(message + os.linesep, to_print=True, report=args.report)
            clearmem(message)
            par(os.linesep, report=args.report)

        elif args.tool == 'dict_analyzer':

            dict_words = []
            with resource_stream('aspgen', 'common_words.txt') as in_handle:
                for word in in_handle:
                    word = word.strip()
                    dict_words.append(word)

            password = getpass()

            par('Password: ' + password, report=args.report)
            par(os.linesep, report=args.report)
            par(os.linesep, report=args.report)

        stats = None

        if args.tool == 'dict_generator' and args.stats is True:
            par('Password Stats' + os.linesep, report=args.report)
            par('--------------' + os.linesep, report=args.report)
            par(os.linesep, report=args.report)
            stats = password_stats(pass_len=args.length,
                                   num_parts=len(dict_words),
                                   guess_speeds=args.guess_speeds,
                                   verbose=args.secure)
            stats['combinations_raw'] = 26 ** len(password)
            stats['entropy_raw'] = log(stats['combinations_raw'], 2)

        elif args.tool == 'dict_analyzer':
            par('Password Stats' + os.linesep, report=args.report)
            par('--------------' + os.linesep, report=args.report)
            par(os.linesep, report=args.report)
            stats = password_stats(dict_pass=password,
                                   dictionary=dict_words,
                                   guess_speeds=args.guess_speeds,
                                   verbose=args.secure)
            par('Words in Password: {0}{1}'
                .format(' '.join(stats['words']), os.linesep),
                to_print=True, report=args.report)

        if args.tool == 'dict_analyzer' or args.stats is True:
            c, e = print_stats(stats['combinations'], stats['entropy'])
            par(c + os.linesep, to_print=True, report=args.report)
            par(e + os.linesep, to_print=True, report=args.report)
            if args.guess_speeds is not None:
                par('{0}Average Time to Cracked Password'.format(os.linesep)
                    + os.linesep, to_print=True, report=args.report)
                par(str(stats['guess_table']), to_print=True,
                    report=args.report)
                par(os.linesep, report=args.report)

        if stats is not None and stats['entropy_raw'] < stats['entropy']:
            par(os.linesep, to_print=True, report=args.report)
            par('!' * 79 + os.linesep, to_print=True, report=args.report)
            par('!' + 'WARNING'.center(77) + '!' + os.linesep,
                to_print=True, report=args.report)
            par('!' * 79 + os.linesep, to_print=True, report=args.report)
            par(os.linesep, to_print=True, report=args.report)
            par('Your password is more vulnerable to brute force '
                + os.linesep, to_print=True, report=args.report)
            par('attacks than dictionary attacks. Consider generating '
                + os.linesep, to_print=True, report=args.report)
            par('a dictionary password with more words or longer words.'
                + os.linesep, to_print=True, report=args.report)
            par(os.linesep, to_print=True, report=args.report)
            par('Brute Force Stats' + os.linesep, to_print=True,
                report=args.report)
            par('-----------------' + os.linesep, to_print=True,
                report=args.report)
            par(os.linesep, to_print=True, report=args.report)
            c, e = print_stats(stats['combinations_raw'], stats['entropy_raw'])
            par(c + os.linesep, to_print=True, report=args.report)
            par(e + os.linesep, to_print=True, report=args.report)

        par(os.linesep, report=args.report)

        for word in dict_words:
            clearmem(word)

        clearmem(password)


if __name__ == '__main__':  # TODO: update guesses argument
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.
                                     RawDescriptionHelpFormatter)
    parser.add_argument('-r', '--report',
                        default=None,
                        type=argparse.FileType('w'),
                        help='generate runtime report, contains sensitive '
                             'data')
    subparsers = parser.add_subparsers(title='Tools',
                                       dest='tool')

    analyzer = subparsers.add_parser('analyzer',
                                     help='Analyze a given password')
    analyzer.add_argument('-g', '--guess_speeds',
                          nargs='+',
                          type=float,
                          help='password guesses per second by hacker')

    dict_analyzer = subparsers.add_parser('dict_analyzer',
                                          help='Analyze a dictionary-based '
                                               'password')
    dict_analyzer.add_argument('-g', '--guess_speeds',
                               default=None,
                               nargs='+',
                               type=float,
                               help='password guesses per second by hacker')
    dict_analyzer.add_argument('-m', '--min_length',
                               default=5,
                               type=int,
                               help='minimum length word to use in password')
    dict_analyzer.add_argument('-t', '--detailed',
                               action='store_true',
                               help='produce detailed password stats, '
                                    'interpret results with a grain of salt')
    dict_analyzer.add_argument('-x', '--max_length',
                               default=999,
                               type=int,
                               help='maximum length word to use in password')

    dict_generator = subparsers.add_parser('dict_generator',
                                           help='Securely generate a '
                                                'dictionary-based password')
    dict_generator.add_argument('-g', '--guess_speeds',
                                default=None,
                                nargs='+',
                                type=float,
                                help='password guesses per second by hacker')
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
                                help='print stats on password')
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
    generator.add_argument('-g', '--guess_speeds',
                           default=None,
                           nargs='+',
                           type=float,
                           help='password guesses per second by hacker')
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
                           help='print stats on password')
    generator.add_argument('-u', '--upper_letters',
                           action='store_true',
                           help='permit uppercase letters in password')
    args = parser.parse_args()

    # TODO: add security settings

    # Easter Egg
    # 3.5e+8: gizmodo/5966169/the-hardware-hackers-use-to-crack-your-passwords
    # 4.0+12 AntMiner S7
    # 1.0e+16 NSA?
    if hasattr(args, 'guess_speeds') is True and args.guess_speeds == [0]:
        args.guess_speeds = [3.4e+8, 4.0e+12, 1.0e+16]

    # Print fanciful output to record password generation information
    if args.report is not None:
        par('-' * 79 + os.linesep, report=args.report)
        par('aspgen V{0}'.format(__version__).center(79) + os.linesep,
            report=args.report)
        par('-' * 79 + os.linesep, report=args.report)
        par(os.linesep, report=args.report)
        par('Parameters' + os.linesep, report=args.report)
        par('----------' + os.linesep, report=args.report)
        par(os.linesep, report=args.report)
        lines = textwrap.wrap('Command: {0}'.format(
                                             os.linesep.join(sys.argv[:])), 79)
        for line in lines:
            par(line + os.linesep, report=args.report)
        for arg in vars(args):
            par('{0}: {1}'.format(arg, getattr(args, arg)) + os.linesep,
                report=args.report)
        par(os.linesep, report=args.report)
        par('Environmental Data' + os.linesep, report=args.report)
        par('------------------' + os.linesep, report=args.report)
        # TODO: Fill in this section
        par(os.linesep, report=args.report)
        par('Password' + os.linesep, report=args.report)
        par('--------' + os.linesep, report=args.report)
        par(os.linesep, report=args.report)

    main(args)

    if args.report is not None:
        par('-' * 79 + os.linesep, report=args.report)
        par('Exiting aspgen V{0}'.format(__version__).center(79) + os.linesep,
            report=args.report)
        par('-' * 79 + os.linesep, report=args.report)

    sys.exit(0)
