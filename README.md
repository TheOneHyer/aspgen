# aspgen

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#install)
3. [Usage](#usage)
    * [HELP!](#help)
    * [Global Arguments](#global-arguments)
    * [Generator](#generator)
    * [Analyzer](#analyzer)
    * [Dictionary Generator](#dictionary-generator)
    * [Dictionary Analyzer](#dictionary-analyzer)
    * [Decrypter](#decrypter)
4. [Examples](#examples)
    * [README Examples](#readme-examples)
    * [Generator Examples](#generator-examples)
    * [Analyzer Example](#analyzer-example)
    * [Dictionary Generator Examples](#dictionary-generator-examples)
    * [Dictionary Analzyer Example](#dictionary-analyzer-example)
    * [Decrypter Example](#decrypter-example)
5. [Theory and Implementation](#theory-and-implementation)
    * [Password Security](#password-security)
    * [Dictionary Passwords](#dictionary-passwords)
    * [Environmental Security](#environmental-security)
6. [Inspiration](#inspiration)
7. [Bugs](#bugs)
8. [Roadmap](#roadmap)
    * [V1.0](#V1.0)
    * [V1.1](#V1.1)
    * [V1.2](#V1.2)
    * [V2.0](#V2.0)
    * [V3.0](#V3.0)

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

*Note: aspgen only works with Python 2.7*

## Usage

aspgen aims to be intuitive and simple enough that you hopefully won't
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

readme also includes a '--header' option to only print a section of this
readme corresponding to given header. Available headers can be viewed
via the '--list_headers' option.
See [README Examples](#readme-examples) for '--header' examples.

### Global Arguments

There are three "global" arguments in aspgen. Each such argument and
the tools they apply to are provided:

--encrypt \<key file\>: Applies to both generator and analyzer tools.
                        Encrypts report file (see below) and creates the
                        key file to decrypt the report file. The AES256
                        algorithm is used to perform encryption.
                      
--report \<report file\>: Applies to both generator and analyzer tools.
                          Writes detailed report to report file
                          containing the password, password statistics,
                          and various runtime data.
                        
--system_entropy \<integer\>: Only applies to generator tools. 
                              Minimum system entropy required before
                              aspgen will generate a password. If system
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
       for the above character sets negates this flag. \[Default\]
       
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
                       which are representative guess speeds
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
only possible under the aforementioned restraint.
aspgen's dictionary analyzer usage follows:

`aspgen <global arguments> dict_analyzer <dict_analzyer arguments>`

--guess_speeds: See generator --guess_speeds less last sentence.
                          
### Decrypter
Solely as a convenience, aspgen provides a decryption function that
takes and encrypted report file and its associated key in order to
read the report file and print it to the terminal screen:

`aspgen decrypter <report file> <key file>`

## Examples

The following examples demonstrate how to use aspgen. They all use the
shorthand notation of flags (available via '--help'):

### README Examples:

* Print of all of README to screen:
    - `aspgen readme`
    
* Print headers in README:
    - `asgpen readme --list_headers`
    
* Print everything under [Usage](#usage), including subsections:
    - `aspgen readme --header usage`
    
* Only print this subsection (*note: quotes permit spaces in request*):
    - `aspgen readme --header 'readme examples'`

### Generator Examples

* Generate a password containing all letters and numbers that is 12
  characters long:
    - `aspgen generator -l 12 -p`
    
* Generate a password with lowercase letters and special characters
  that is 15 characters long and calculate statistics on it:
    - `aspgen generator -l 15 -o -n -t`
    
* Generate a password using all characters, calculate statistics,
  guess the longevity of the password, and save an encrypted report:
    - `aspgen -e report.key -r report generator -a -g 0 -t`
    
### Analyzer Example

* Analyze a user-given password, guess password hacking times, and print
  report:
    - `aspgen -r report.txt analyzer -g 10000000 250000000`
    
### Dictionary Generator Examples

* Generate a dictionary password containing five words of five letters
  or larger:
    - `aspgen dict_generator -l 5 -m 5`
    
* Generate a dictionary password containing four words of three letters
  or fewer and calculate statistics:
    - `aspgen dict_generator -l 4 -x 3 -t`
    
* Generate a dictionary password using most words in the English
  language of six or greater letters, calculate statistics, guess
  hacking speed, and save and encrypted report:
    - `aspgen -e report.key -r report dict_generator -u -m 6 -g 0 -t`
    
### Dictionary Analyzer Example

* Analyze a user-given dictionary password and save report:
    - `aspgen -r report dict_analyzer`
    
### Decrypter Example

* Decrypt an encrypted report file:
    - `aspgen decrypter report report.key`
    
## Theory and Implementation

This brief section details the theory behind password security, password
generation, and how these concepts influence aspgen's design.

### Password Security

Password security essentially boils down to how quickly a hacker can
guess a given password. While numerous software implementations work
to improve any given password's security, e.g. limiting password entries
per second or limiting total allowable password guesses, there is no
substitute for a strong password. This problem is compounded when
working in environments where a hacker's password cracking speed is
only limited by their hardware as specialized hardware can guess
trillions of password hashes (semi-encrypted passwords) per second.

A secure password is simply a password that is harder/takes longer
to guess. In the worst-case scenario for a hacker, he or she will simply
have to guess every possible password combination until they just
happen to guess your password. This is known as a brute force attack and
is the most ideal situation for you and least ideal situation for a
hacker as it maximizes the amount of time before a password is guessed.
A password must be constructed by choosing characters at complete
random to guarantee a hacker must resort to a brute fore attack.
Passwords generated via heuristics such as using sequences of letters
or numbers, using words relevant to your life, or altering words with
l33t are inherently weak as they give hackers a method to quickly guess
your password. For secure passwords, only completely random passwords
suffice. As such, aspgen generates passwords by randomly selecting
each character or word of your password from a set of available
characters/words using your operating system's entropy generator.

Once a hacker resorts to brute force attack, the security of a password
relies on the possible number of passwords generated by a given method.
For random passwords, the number of possible passwords equals the
following equation:

combinations = (number of possible characters) ^ (password length)

Therefore, secure passwords are both complex (more characters) and/or
longer. aspgen allows you to select both the length of a password and
available characters, and thus select your own password strength.
aspgen can also calculate password combinations based on your chosen
parameters. It will also calculate the entropy of a password given by:

log2(password combinations)

and guess the average time in seconds required to guess a generated
or user-provided password at a given passwords/sec guess speed. This
calculation assumes that your password is randomly generated; a
randomly generated password of X possible possible combinations assumes
an uniform distribution. Thus, on average, guessing any single password
requires guessing half of all possible password combinations.
Ultimately, this means that guessing any single password requires enough
time to guess half of all possible password combinations. So, the time
to guess a password is:

time to guess = (password combinations) / 2 / (password guesses / sec)

This calculation assumes that a hacker knows your exact number of
password combinations, and thus both the exact length and character set
of your password. As a result, this calculation can be thought of as an
effective minimum time (on average) to guess a password for most
realistic scenarios.

In summary, secure passwords are random, long, and "complex". aspgen
always generates random passwords and the user has the power to control
password length and character set.

### Dictionary Passwords

The internet is full of contention concerning the security of dictionary
passwords. Some argue that dictionary passwords are secure due to their
(normally) long length and ease of human memorization: preventing
insecure practices such as writing passwords. Others detest dictionary
passwords as they permit hackers to use a dictionary attack: simply
guessing combinations of words in the dictionary rather than all
possible characters.

Luckily, simple math solves this dilemma. When using a list of words to
generate a password, each word becomes a "character" than can be
randomly selected and the "length" of the password is simply the number
of words used in the password. Thus:

password combinations = (words in list) ^ (words in password)

which should be familiar. Most secure dictionary passwords use five to
seven words which is roughly half the length of most secure
"traditional" passwords but the number of words in a list can far
exceed the number of ASCII characters. The large base results in a
very secure password that is also easy for humans to memorize. As an
example, a six word password made from a 10,000 word list has an
entropy of 79.73, while an eight character password made from from all
95 printable ASCII characters has an entropy of 52.56. Thus, the
dictionary password is more secure and will always be easier to
memorize. aspgen will inform you if your dictionary password is so small
that it is easier to hack via brute force attack than dictionary attack.

A brief example of why dictionary passwords are easy to memorize is in
order. This is a traditional, eight character password:

"+Jx*OMv

and here is a seven word dictionary password:

Words: register joiner bloated debauch automotive cupola ballot
Password: registerjoinerbloateddebauchautomotivecupolaballot

The traditional password is hard to memorize and easy to forget. The
dictionary password is easy to remember because one can make a sentence
or acronym out of it, e.g.

A person wants to REGISTER to become of JOINER of BLOATED dancer to
DEBAUCH AUTOMOTIVE owned CUPOLA's for voting BALLOTs.

or whatever else suits your fancy. Additionally, this password is very
hard to hack as a dictionary password due to the sheer number of words
used to generate it, and as a traditional password due to its extreme
length (50 letters). The first password has a entropy of 52.56
whereas the dictionary password has an entropy of 79.83 when hacked
by a dictionary attack, and an entropy of 235.02 against a brute force
attack.

In summary, dictionary passwords are far stronger for their ease of
memorization and should thus be used where possible. In some situations,
such as many online account passwords, your password length is too
limited to permit dictionary passwords, and thus favor "traditional"
passwords. However, in general, I recommend dictionary passwords.

### Enviromental Security

A powerful password is useless if a hacker obtains it when you generate
it. To prevent hackers on your system from obtaining your password,
aspgen secures its runtime environment to potential attacks. This is
accomplished by:

1. Disabling Core Dumps: Core dumps are files written to disk of your
                         program's data when it crashes. In aspgen, this
                         data includes your password. By disabling the
                         core dump, your password will never be written
                         to disk for hackers to view in case aspgen
                         dies.
                         
2. Ensure Minimum Entropy: All widely used operating systems have ways
                           to generate randomness. Using this randomness
                           to perform operations "consumes" it. If the
                           system entropy is too low, processes relying
                           on it will cease to be random. aspgen ensures
                           the system entropy is sufficient to generate
                           a password before proceeding with password
                           generation.
                           
3. Encrypting Report: The report file created by aspgen contains the
                      password generated or analyzed. To prevent hackers
                      from reading this file, aspgen can encrypt the
                      file in memory before writing it to the disk.
                      
4. Clearing Memory: The moment aspgen no longer needs your password in
                    memory, it burns a hole through the memory so as to
                    remove all possible references to your password.
                    This minimizes numerous possible attacks that
                    involve gaining access to memory buffers.
                    (This functionality limits aspgen to Python 2.7)
                      
I also attempted to prevent aspgen from paging memory so that data never
ends up on the disk, but any attempts to do so with the kernel calls
mlock() and mlockall() were unsuccessful. Since aspgen tends to use
40 MB of memory at greatest, and completes in less than a second, paging
should rarely be issue, but still exists. Fixing this may require a C++
wrapper for aspgen, or simply rewriting aspgen in C++. C++ is currently
beyond my knowledge set, but I intend to learn it eventually and
appreciate any outside help (go open-source!).

## Inspiration

aspgen was inspired by a surprising lack of good, safe, easily
accessible, open-source password generators. Some programs have built-in
password generators of some kind, but not as standalone programs that
also give users the statistics needed to ensure their password is
secure. There are also many online password generators, but browsers
may not be secure on either the client side (browser software hacked)
or server side (website code maliciously stores/or and retrieves your
password). Still more password generating software cost money--
ridiculous. In essence, secure password generation doesn't exist in a
user friendly manner and thus aspgen was born.

## Bugs

There are currently no known bugs with aspgen V1.1. Please report all
reproducible bugs to theonehyer@gmail.com. aspgen is only tested with
Python 2.7 on Ubuntu 16.04 LTS during production and tested on CentOS 7 once
before a "Stable" version is released.

## Roadmap

### V1.0

Initial version. Documented and completed.

### V1.1

Internal code changes to permit a more intuitive and manipulable internal 
structure with easier-to-import functionality.

### V1.2

Add Unicode support. Add ability for user to create custom include/exclude 
lists.

### V2.0

aspgen 2.0.0 will sport a TUI (Text User Interface) using
[URWID](http://http://urwid.org/). Hopefully, a TUI will make aspgen 
extremely intuitive and convenient.

### V3.0

While I have not officially decided if I will write aspgen 3.0.0, if I
do, it will provide an X11 windowing system for use with GUI
(Graphical User Interfaces) systems. As an open-source project, I
greatly appreciate all help and will give full credit to any
contributions.
