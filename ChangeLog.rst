Changelog
=========

%%version%% (unreleased)
------------------------

- Updated GitChangeLog and Versioning. [TheOneHyer]

  Attempted fixes at GitChangeLog config and
  updated setup.py version number.

- Whole Project Now Uses Unicode Literals. [TheOneHyer]

- Branched V1.2 to Add Unicode Support. [TheOneHyer]

- Modified setup.py version. [TheOneHyer]

1.1.0 (2016-12-20)
------------------

- Finalized aspgen V1.1. [TheOneHyer]

- Updated __init__ version. [TheOneHyer]

- Small Code Redundancy Removed. [TheOneHyer]

  Opened memory file when attribute is defined instead of the line after.
  aspgen appears functional but will wait one day min before
  testing.

- Added Bugs to README, Improved Roadmap. [TheOneHyer]

  Divided Roadmap section of README into subsections for each version.
  Added Bugs section to README.

- Streamlined Guess Table, add ChangeLog.rst. [TheOneHyer]

  Created guess_table() to reduce code redundancy when generating
  guessing table for password. Project upped to release candidate
  as all changes planned for V1.1 complete and just need testing.

- Streamlined password_stats. [TheOneHyer]

  password_stats() now only calculated stats for non-dictionary passwords.
  Excess code removed.

- Added Documentation to dict_stats. [TheOneHyer]

  dict_stats() now has proper documentation. V1.1 status changed to
  trove classifier Alpha.

- Reorganized entry() and main() [TheOneHyer]

  Program now entirely in main() and entry() is just an access point for
  command-line access to aspgen.

- Added dict_stats. [TheOneHyer]

  dict_stats now used to calculate statistics when using
  the tool dict_analyzer. Fixed bug to actually write report file
  caused when report files kepy in memory.

- Replaced Output with Memory File. [TheOneHyer]

  Output report is now always placed in memory and
  written at the end of aspgen.

- Replaced Output with Memory File. [TheOneHyer]

  Output report is now always placed in memory and
  written at the end of aspgen.

1.0.0 (2016-11-16)
------------------

- Aspgen Released. [TheOneHyer]

  aspgen released version 1.0.0!

- Added --list_headers. [TheOneHyer]

  readme tool now has a list_headers argument
  that prints available headers and exits.

- Lowered Default Entropy. [TheOneHyer]

  Lowered default system entropy to better fit actual
  password generation entropy usage.

- Fixed Typo in README. [TheOneHyer]

- Putatively Completed aspgen. [TheOneHyer]

  aspgen is complete less even more thorough field
  testing.

- Added More Sections to README. [TheOneHyer]

  Added a Roadmap section to README as well as
  a dictionary password example.

- README Complete. [TheOneHyer]

  README is "complete" and so is aspgen. A fewer minor
  modifications and additional documentation may be
  added before the final release.

- Limited Entropy Check and Added Security to README. [TheOneHyer]

  aspgen now only checks entropy when generating
  a password. Added Environmental Security section to
  README.

- Added Dictionary Password section to README. [TheOneHyer]

- Fixed Links in README. [TheOneHyer]

  README link anchors are now lowercase

- Added Password Security to README. [TheOneHyer]

  Password Security theory, calculations, and aspgen
  implementation added to README.

- Added Password Security to README. [TheOneHyer]

  Password Security theory, calculations, and aspgen
  implementation added to README.

- Added Password Security to README. [TheOneHyer]

  Password Security theory, calculations, and aspgen
  implementation added to README.

- Added Theory to README. [TheOneHyer]

  README now has header of Theory section.

- Added --header to README. [TheOneHyer]

  aspgen readme command now has a '--header' option to
  only print out a subset of the README to reduce noise.
  README updated to reflect this addition.

- Updated README. [TheOneHyer]

  Added Examples section

- Updated README. [TheOneHyer]

  Added rest of Usage section

- Updated README. [TheOneHyer]

  Added Global Arguments and Generator sections

- Updated README. [TheOneHyer]

  Added Intro and Installation sections

- Added README.md to MANIFEST. [TheOneHyer]

- Reverted Executable. [TheOneHyer]

  Executable is now a console_script again w/ slight code
  reorganization for ease of use.

- Changed Executable Style. [TheOneHyer]

  aspgen given as script instead of entry point

- Added Documentation, Rolled Release Forward. [TheOneHyer]

  aspgen now at version RC1. More documentation
  throughout aspgen but especially in __doc__

- Added Environmental Security. [TheOneHyer]

  aspgen cannot core dump and ensures minimum system
  entropy before password generation.

- Added Output Encryption and Decryption. [TheOneHyer]

  aspgen can now encrypt output and decrypt it again.

- Program Output More Intuitive. [TheOneHyer]

  aspgen writes different output to STDOUT and
  report files. STDOUT output simplified.

- Merge remote-tracking branch 'origin/master' [TheOneHyer]

  # Conflicts:
  #	aspgen/aspgen.py

- Improved Program Output. [TheOneHyer]

  aspgen now outputs in a pretty format.

- Program Output More Powerful. [TheOneHyer]

  aspgen can now write output to files and pipes.

- Rolled Project Forward. [TheOneHyer]

  Given near completion status. aspgen has been moved
  to beta.

- Functionally Completed aspgen. [TheOneHyer]

  aspgen is complete and simply needs more documentation.

- Dictionary Deleted from Memory. [TheOneHyer]

  Dictionary used for password generation and analysis
  now deleted after use.

- Dict Functions now use Password_Stats. [TheOneHyer]

  Dictionary related functions now use password_stats.
  Issue with guess_tables using generator still
  unresolved.

- Analyzer and Generator User password_stats. [TheOneHyer]

  Analyzer and Generator tools now user password_stats
  function. However, printing the PrettyTable
  breaks with the generator but not the analyzer.
  Requires more testing.

- Added Guessing Tables to Password Stats. [TheOneHyer]

  Added PrettyTable output to password_stats

- Added Dictionary Password Statistics. [TheOneHyer]

  Added dictionary password calculations for
  both dictionary passwords and their ASCII
  partners.

- Added Flags and Calculations to password_stats. [TheOneHyer]

  password_stats now calculates basic stats and some
  dictionary stats: untested.

- Added Assertion Statements to password_stats. [TheOneHyer]

  passw0rod_stats now uses assertion statements to
  aggressively ensure it only receives the minimum
  possible information.

- Added password_stats Function. [TheOneHyer]

  Added new, monolithic function password_stats
  to reduce code and provide importability
  to password statistics calculating functionality
  of aspgen. Only documentation of function has
  been provided. Code to come.

- Dict_Generator uses generate_password. [TheOneHyer]

  dict_generator tool now uses generate_password
  function to remove redundant code. generate_password
  can now return password parts for analysis.

- Moved Password Generation to Function. [TheOneHyer]

  Password generation is now in a function
  to enable greater modularity. README deleted.

- Updated tarball. [TheOneHyer]

  GitHub tarball URL not in sync w/
  package: recitifed.

- Alphanumeric setting now works. [TheOneHyer]

  Alphanumeric flag is now fully functional.

- Fixed numbers issue in aspgen. [TheOneHyer]

  aspgen will not put numbers in password when numbers
  flag specified

- Passwords Deleted from Memory. [TheOneHyer]

  Passwords, and anything used to construct
  those passwords, are aggressively erased from
  memory the moment they are not needed.

- Aspgen now only supports Python 2.7. [TheOneHyer]

  To securely erase passwords from memory, aspgen
  uses SecureString which only works for Python 2.7.
  output functioned erase since it caused errors and
  also proved a security hazard.

- Added crack_speeds. [TheOneHyer]

  Added crack_speeds function which performs simple
  calculations to guess at how long it would
  take to guess your password.

- Fixed Entropy Calculations. [TheOneHyer]

  Entropy calculation for dictionary passwords
  was backwards. Has been righted.

- Fixed Bracket Problem. [TheOneHyer]

  Double brackets were throwing ValueErrors with format
  in longer passwords. Used '%' operator to
  circumvent issue.

- Added more TODOs. [TheOneHyer]

  Added every todo I could think of for aspgen

- Added dict_analyzer. [TheOneHyer]

  Split analyzer into "analyzer" and "dict_analyzer"
  to better handle dictionary passwords. Added many
  todos

- Analyzer uses getpass. [TheOneHyer]

  Analyzer tool now uses getpass module to
  hide user input.

- Added examples to functions made executable. [TheOneHyer]

  Added examples to most functions in aspgen. Made
  aspgen.py executable.

- Password stats streamlined. [TheOneHyer]

  Printing password stats now in a single function.
  This function uses Decimal to be robust to large
  passwords. Issue with brackets in large passwords,
  requires investigation.

- Analyzer now functions at basic level. [TheOneHyer]

  Analyzer tool now produces stats output. This
  output is the same as producing a passwords
  with the stats option set. Will be expanded
  soon.

- Updated dict_stats. [TheOneHyer]

  dict_stats now break passwords apart using infer_spaces

- Added Word-Finding Algorithm. [TheOneHyer]

  Added algorithm to find words in a string.
  Will be used downstream to analyze dictionary
  passwords.

0.0.3 (2016-07-17)
------------------

- Added dictionary password generator. [TheOneHyer]

  Added two word lists and a fully functioning
  dictionary generator to aspgen.

0.0.2 (2016-06-17)
------------------

- Added basic_stats. [TheOneHyer]

  Added basic_stats function to aspgen to
  calculate password randomness.

- Functional passwords generated. [TheOneHyer]

  aspgen can now functionally output
  crypotgraphically secure passwords.

0.0.0 (2016-06-09)
------------------

- Creating Project Structure. [TheOneHyer]

  Boiler plate directories and files.

- Initial commit. [Alex Hyer]


