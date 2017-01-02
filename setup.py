#! /usr/bin/env python
# -*- coding: UTF-8 -*-

"""Setup file to build and install aspgen PyPI package

Copyright:

    setup.py build and install aspgen PyPI package
    Copyright (C) 2016  Alex Hyer

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import unicode_literals

from setuptools import setup

__author__ = 'Alex Hyer'
__email__ = 'theonehyer@gmail.com'
__license__ = 'GPLv3'
__maintainer__ = 'Alex Hyer'
__status__ = 'Alpha'
__version__ = '1.2.0a6'

setup(name='aspgen',
      version='1.2.0a6',
      description='A Secure Password GENerator',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: End Users/Desktop',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2.7',
          'Topic :: Security'
      ],
      keywords='secure password generator',
      url='https://github.com/TheOneHyer/aspgen',
      download_url='https://github.com/TheOneHyer/aspgen/tarball/1.2.0a6',
      author='Alex Hyer',
      author_email='theonehyer@gmail.com',
      license='GPLv3',
      packages=['aspgen'],
      include_package_data=True,
      zip_safe=False,
      entry_points={
          'console_scripts': [
              'aspgen = aspgen.aspgen:entry'
          ]
      },
      requires=[
          'Crypto',
          'prettytable',
          'SecureString'
      ]
      )
