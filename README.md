#aspgen

## Table of Contents
1. [Introduction](#Introduction)
2. [Installation](#Install)
3. [Usage](#Usage)
    * [HELP!](#HELP!)
    * [Generator](#Generator)
    * [Global Arguments](#Global-Arguments)
    * [Analyzer](#Analyzer)
    * [Dictionary Generator](#Dictionary-Generator)
    * [Dictionary Analyzer](#Dictionary-Analyzer)
    * [Decrypter](#Decrypter)

## Introduction

aspgen (A Secure Password GENerator) is an intuitive, easy-to-use,
Python-based program that generates secure passwords securely, i.e.
secures the runtime environment as much as Python allows. In addition
to generating secure passwords, aspgen also analyzes generated and
user-input-ed passwords for "hackability" (entropy and time-to-guess).
This README will start with a detailed description of aspgen's power
and how to harness it followed by a theoretical description of
password security and aspgen's implementations.

## Installation

`pip install aspgen`

*Note: aspgen only works with Python 2.7 and only works on \*nix
systems*

## Usage

aspgen aims to be intuitive and simple such that you hopefully won't
even need to read this README (though you still should). In general,
aspgen consists of a series of tools following the `aspgen` command as
follows:

`aspgen <global arguments> <tool> <tool specific arguments>`
 
The tools for how to obtain help, generate passwords, analyze passwords,
and store/read reports--and their respective arguments--follow.

### HELP!

aspgen contains the "--help" flag (like every Python program using
argparse) that prints both a brief help and copyright in addition to
the usual argument and tool descriptions. In addition, aspgen also
includes a tool called "readme" that (you guessed it) prints this
readme and exits. The tool can be accessed via:

`aspgen readme`

### Global Arguments

There are three "global" arguments in aspgen. Each such argument and
the tools they apply to are provided:

--encrypt \<key file\>: Applies to both generator and analyzer tools.
                      Encrypts report file (see below) and creates the
                      key file to decrypt the report file. The AES256
                      algorithm is used to perform encryption.
                      
--report \<report file\>: Applies to both generator and analyzer tools.
                        Writes detailed report to report file containing
                        the password, password statistics, and various
                        runtime data.
                        
--system_entropy \<integer\>: Only applies to generator tools. 
                            Minimum system entropy required before
                            aspgen will generate a password. If syst bem
                            entropy is below this level, aspgen will
                            sleep until entropy is high enough to
                            generate a password.

### Generator

The generator tool is the core tool in aspgen. As the name implies,
it produces passwords! More usefully, aspgen allows you to customize
your password's composition as per your requirements (*note: only
ASCII characters are permitted in the password*):

`aspgen <global arguments> generator <generator arguments>`

--all: Permit lowercase and uppercase letters, numbers, and special
       characters in the password. Specifying any of the four arguments
       for the above character sets negates this flag. [Default]
       
--alphanumeric: Permit lowercase and uppercase letters and numbers in
                generated password.

--guess_speeds \<number\> \<number\> ... \<number\>:
                       Space-separated list of numbers. Each number
                       represents the password guessing speed
                       in passwords/sec a hacker can employ
                       to hack the given/generated password. Outputs
                       a table depicting the average number of seconds
                       required to guess the password at each speed.
                       Entering `--guess_speed 0` defaults to 
                       `--guess_speeds 3.4e+8 4.0e+12 1.0e+16`
                       which represent some representative guess speeds
                       of gaming computes, AntMiner S7, and a putative
                       NSA speed respectively. Does nothing if
                       --stats is not specified.
                       
--length \<integer\>: Number of characters in generated password.

--numbers: Permit numbers in password.

--lower_letters: Permit lowercase letters in generated password.

--special_characters: Permit special characters in generated password.

--stats: Calculate various password statistics.

--upper_letters: Permit uppercase letters in generated password.

### Analyzer

The aspgen analyzer takes in a user password, analyzes its composition,
and produces a statistics report. It is used as such:

`aspgen <global arguments> analyzer [--guess_speeds]`

--guess_speeds: See generator --guess_speeds less last sentence.

### Dictionary Generator

Generates a customizable dictionary password using the 10,000 most
common words in the English language by default. See below for my
arguments supporting dictionary passwords. aspgen's dictionary generator
is used as follows:

`aspgne <global arguments> dict_generator <tool specific arguments>`

--guess_speeds: See generator --guess_speeds.

--length \<integer\>: Number of words in generated password.

--min_length \<integer\>: Maximum word length permitted in generated
                          password.

--min_length \<integer\>: Minimum word length permitted in generated
                          password.

--stats: Calculate various password statistics. Will throw warning if
         guessing the dictionary password using brute force attacks is
         harder than a dictionary attack.
         
--uncommon: Permit approximately all words in English language
            (300,000+) instead of 10,000 most common words. *Warning:
            passwords generated with this flag will be very hard to
            memorize.*
            
### Dictionary Analyzer

A dictionary password statistics analyzer. This function only works if
the user-provided password consists solely of the 10,000 most common
words in the English language. aspgen will accurately guess the
individual words in your password to calculate statistics but this is
only possible under the aforementioned restraint. Providing
--min_length and --max_length improve this functionalities accuracy.
aspgen's dictionary analyzer usage follows:

`aspgen <global arguments> dict_analyzer <dict_analzyer arguments>`

--guess_speeds: See generator --guess_speeds less last sentence.

--min_length \<integer\>: Maximum word length permitted in given
                          password.

--min_length \<integer\>: Minimum word length permitted in given
                          password.
                          
### Decrypter
Solely as a convenience, aspgen provides a decryption function that
takes and encrypted report file and its associated key in order to
read the report file and print it to the terminal screen:

`aspgen decrypter <report file> <key file>`
