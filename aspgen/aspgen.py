#! /usr/bin/env python

from __future__ import print_function

"""A Secure Password GENerator


"""

import argparse
import os
import random
import sys
from textwrap import wrap

__author__ = 'Alex Hyer'
__email__ = 'theonehyer@gmail.com'
__license__ = 'GPLv3'
__maintainer__ = 'Alex Hyer'
__status__ = 'Alpha'
__version__ = '0.0.2'


def password_characters(all=True, lower_letters=False, upper_letters=False,
                        special_characters=False):
    """Create a list of possible characters for a password

    Args:
        all (bool): same as setting lower_letters, upper_letters, and
                    special_characters all to True

        lower_letters (bool): add lower-case letters to character list

        upper_letters (bool): add upper-case letters to character list

        special_characters (bool): add special characters to character list

    Returns:
        list: List of str characters for password

    Example:
        >>> password_characters(all=False, special_characters=True)
        [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-',
        '.', ':', ';', '<', '=', '>', '?', '[', '\\', ']', '^', '_', '{', '|',
        '}']
    """

    characters = []

    if lower_letters or all:
        characters += [chr(char) for char in range(97, 122)]

    if upper_letters or all:
        characters += [chr(char) for char in range(65, 90)]

    if special_characters or all:
        characters += [chr(char) for char in range(32, 47)]
        characters += [chr(char) for char in range(58, 64)]
        characters += [chr(char) for char in range(91, 96)]
        characters += [chr(char) for char in range(123, 126)]

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
                                    special_characters=args.special_characters)
        max_char = len(chars) - 1

        for i in range(args.length):
            password.append(chars[random.SystemRandom().randint(0, max_char)])
        output(''.join(password))

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
    generator.add_argument('-u', '--upper_letters',
                           action='store_true',
                           help='permit uppercase letters in password')
    args = parser.parse_args()

    main(args)

    sys.exit(0)
