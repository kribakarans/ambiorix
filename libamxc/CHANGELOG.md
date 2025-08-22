# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v2.0.0 - 2024-04-30(06:47:56 +0000)

### New

- add amxc_var_add_value()

### Other

- Improve documentation of amxc_ts_to_tm functions

## Release v1.10.5 - 2024-04-16(21:14:19 +0000)

### Fixes

- Fix inconsistency in converting integer signedness

## Release v1.10.4 - 2024-03-28(18:02:00 +0000)

### Fixes

- Fix crash on converting string variant without buffer to timestamp

## Release v1.10.3 - 2024-02-13(11:09:31 +0000)

### Other

- Functional issues linked to parenthesis escaping in the data model

## Release v1.10.2 - 2024-01-31(11:18:48 +0000)

### Other

- [amx-cli] Allow proper escaping of variable in cli for input and display

## Release v1.10.1 - 2024-01-10(09:51:50 +0000)

### Fixes

- Adapt description of ambiorix packages
- [amx-cli] Allow proper escaping of variable in cli for input and display

## Release v1.10.0 - 2023-11-03(16:10:18 +0000)

### New

- - [prpl][libamxc] amxc_set_to_string only use space as separator

## Release v1.9.0 - 2023-10-17(10:46:25 +0000)

### New

- [libamxc] Some characters in amxc string can have special purpose and it must be possible to escape them

### Other

- Issue ST-1184 [amxb][amxc][amxo][amxrt] Fix typos in documentation
- [amxb][amxc][amxo][amxrt] Fix typos in documentation

## Release v1.8.13 - 2023-09-22(09:53:45 +0000)

### Fixes

- Fix license headers in files

## Release v1.8.12 - 2023-09-14(06:41:34 +0000)

### Changes

- allow amxc_var_dump with FILE*

## Release v1.8.11 - 2023-07-14(13:13:53 +0000)

### Fixes

- When using GCC 12.2 extra compilation wanings pop-up

## Release v1.8.10 - 2023-05-09(14:18:05 +0000)

### Fixes

- [amxc] Fix missing semicolon

## Release v1.8.9 - 2023-04-18(18:18:50 +0000)

### Other

- Fix a typo in the description of amxc_var_add_new_key_amxc_llist_t

## Release v1.8.8 - 2023-04-08(16:55:32 +0000)

## Release v1.8.7 - 2023-01-30(16:26:24 +0000)

### Fixes

- Issue: semgrep reports

## Release v1.8.6 - 2022-11-30(20:42:06 +0000)

### Fixes

- amxp_expr_buildf with 2 arguments only works in container, not on board

## Release v1.8.5 - 2022-11-21(09:15:11 +0000)

### Fixes

- Fix wrong comma in amxc_var_dump output

## Release v1.8.4 - 2022-11-19(11:41:22 +0000)

### Fixes

- Converting an empty string variant to a list should result in an empty list

## Release v1.8.3 - 2022-11-15(11:52:11 +0000)

### Fixes

- Update documentation of functions amxc_var_get_next, amxc_var_get_previous and amxc_var_get_parent

## Release v1.8.2 - 2022-11-14(07:03:53 +0000)

### Fixes

- Investigate and fix klocwork reports for ambiorix libs and tools

## Release v1.8.1 - 2022-11-03(08:51:39 +0000)

### Other

- Issue: ambiorix/libraries/libamxc#69 Remove dead code and code cleanup
- Support appending formatted string with safety check on replacements

## Release v1.8.0 - 2022-10-05(11:38:09 +0000)

### New

- Add comparison implementation for htable variants
-  Add comparison implementation for linked list variants

## Release v1.7.3 - 2022-09-12(12:08:29 +0000)

### Other

- Integrate Devolo Interference Mitigation (integration)

## Release v1.7.2 - 2022-08-26(05:51:43 +0000)

### Fixes

- amxc_string_t does not handle empty strings properly

## Release v1.7.1 - 2022-08-17(08:04:40 +0000)

### Changes

- amxc_string_split_to_llist not splitting text with newline sperator.

## Release v1.7.0 - 2022-07-20(08:30:57 +0000)

### Other

- Improve documentation
- Add when_failed_status macro

## Release v1.6.1 - 2022-05-23(10:12:19 +0000)

### Fixes

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when memory leaks are detected

## Release v1.6.0 - 2022-05-19(14:34:00 +0000)

### New

- Make it possible to initialize a timestamp structure using struct tm

## Release v1.5.1 - 2022-04-06(08:23:18 +0000)

## Release v1.5.0 - 2022-02-14(22:25:55 +0000)

### New

- Add implementation of amxc_var_set_path and amxc_var_set_pathf

## Release v1.4.4 - 2022-02-04(14:12:51 +0000)

### Fixes

- Variant conversions to integer values is going wrong on mips target

## Release v1.4.3 - 2021-11-10(11:57:45 +0000)

### Fixes

- Fixes test when daylight saving is off

## Release v1.4.2 - 2021-10-28(21:31:46 +0000)

## Release v1.4.1 - 2021-10-20(18:03:37 +0000)

### Fixes

- Segmentation fault occurs when NULL pointer passed to amxc_var_dump or amxc_var_log

## Release v1.4.0 - 2021-10-07(12:09:56 +0000)

### New

- Make it possible to get the local time timestamp

## Release v1.3.3 - 2021-09-24(12:27:59 +0000)

### Fixes

- It must be possible to indicate that amxc_var_get_path must not search positional if key is not found

## Release v1.3.2 - 2021-09-23(08:18:12 +0000)

### Fixes

- Unexpected behavior of amxc_var_get_path

## Release v1.3.1 - 2021-09-03(18:00:23 +0000)

## Release v1.3.0 - 2021-09-03(12:24:56 +0000)

### New

- Add functions to convert a string to capital/lower case.
- [status macros] Add when_null_status macros in amxc

### Other

- Generate junit xml files with unit-tests
- Issue: ambiorix/libraries/libamxc#56 Generate junit xml files with unit-tests

## Release v1.2.2 - 2021-08-23(09:48:30 +0000)

### Changes

- no more Shadow warning if nesting of ...for_each... macros is used

## Release v1.2.1 - 2021-07-09(06:48:28 +0000)

### Fixes

- Inconsistency in behavior of constcast and dyncast on string variants

## Release v1.2.0 - 2021-07-02(18:11:41 +0000)

### New

- Make it easy to convert an array of bytes to a hexbinary string and the other way around

## Release v1.1.1 - 2021-06-28(11:58:27 +0000)

### Fixes

- Removes amxc_var_hfor_each

### Changes

- Make it easier to iterate over htable and list variants

## Release v1.1.0 - 2021-06-18(14:52:28 +0000)

### New

- Abstract data type set must be provided

### Changes

- Make it possible to access htable variants by index

## Release v1.0.15 - 2021-06-08(07:51:37 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

## Release v1.0.14 - 2021-05-03(11:30:15 +0000)

### Changes

- Provide public header file for common macros
- Update variant GET macros

### Other

- Enable auto opensourcing

## Release v1.0.13 - 2021-04-23(18:14:04 +0000)

### Fixes

- using function amxc_var_take_it to remove a variant from a list or table segfaults when passing NULL pointer

## Release 1.0.12 - 2021-04-15(19:42:29 +0000)

## Release 1.0.11 - 2021-04-08(19:57:33 +0000)

### Fixes

- csv strings are not always correctly parsed

## Release 1.0.10 - 2021-04-07(19:00:18 +0000)

### Fixes

- Correct copybara rule
- Correct copybara scrubbing order

### Changes

- Move copybara to baf

## Release 1.0.9 - 2021-03-24(10:40:09 +0000)

### Fixes

- amxc_var_get_path is not usable when keys contain dots

## Release 1.0.8 - 2021-03-10(10:26:52 +0000)

### Changes

- Extend string variant conversion to bool

## Release 1.0.7 - 2021-02-25(12:43:10 +0000)

### Changes

- API documentation mentions AMXC_VAR_FLAG_XXXX instead of full names
- API Documentation iterator APIs should be put in a sub-group
- Migrate to new licenses format (baf)

## Release 1.0.6 - 2021-02-14(07:40:29 +0000)

### Fixes

- Documentation is not matching implementation

## Release 1.0.5 - 2021-01-27(14:04:12 +0000)

### Changes

- Add doxygen documentation tags to all public APIs

## Release 1.0.4 - 2021-01-18(14:16:53 +0000)

### Fixes

- Fixes indentation in var dump for array in array
- Only include objects in static library

## Release 1.0.3 - 2021-01-04(10:47:15 +0000)

### Changes

- Collect parts when split fails

### Fixes

- Variant logging
- Variant dump indentation

## Release 1.0.2 - 2020-12-04(08:15:16 +0000)

### New

- Automatic conversions of variants containing a string
- Add a function to set a 0 terminating string into an amxc_string buffer

## Release 1.0.1 - 2020-11-30(13:43:50 +0000)

### Changes

- Updates baf file - used for generating makefiles and build system files

## Release 1.0.0 - 2020-11-29(15:10:50 +0000)

### New

- It must be possible to move the content of one variant into another variant

### Changes

- Merge branch 'dev-baf' into 'master'

### Fixes

- Set last char to 0 when trimming
- Fixes amxc_string_copy and add tests
- amxc_string_reset should set buffers first element to 0

## Release 0.7.9 - 2020-11-25(18:51:37 +0000)

### Fixes

- Fix variant.md doc typo

## Release 0.7.8 - 2020-11-25(08:16:09 +0000)

### New

- Add amxc_string_replace function
- Add amxc_string_search function

### Changes

- Switch order in updating variant htable, first add and then remove


## Release 0.7.7 - 2020-11-21(12:04:07 +0000)

### Changes

- Adds and updates doxygen documentation of variant APO
- Allow amxc_string_join_llist with const llists
- Update readme

### New

- `amxc_var_take_it` removes a variant from a htable and/or llist
- `amxc_var_take_key` removes a variant from a htable and/or llist by key
- `amxc_var_take_index` removes a variant from a htable and/or llist by index

## Release 0.7.6 - 2020-11-16(09:04:58 +0000)

### Changes

- Adds doxygen documentation tags

## Release 0.7.5 - 2020-11-08(19:19:27 +0000)

### New

- Adds amxc_string_join_var_until
- Adds GETI_XXX macros

### Fixes 

- Fix typos in variant.md

## Release 0.7.4 - 2020-11-01(21:15:22 +0000)

### Fixes

- Complete timestamp API tests
- Add timestamp api documentation

## Release 0.7.3 - 2020-10-27(17:21:04 +0000)

### Fixes

- Converting htable variant to string variant segfaults

## Release 0.7.2 - 2020-10-19(18:39:06 +0000)

### Changes

- Update documentation variant.md - add 8 and 16 bit integers

## Release 0.7.1 - 2020-10-14(05:52:36 +0000)

### New

- Variant types int8, uint8, int16, uint16

## Release 0.7.0 - 2020-10-02(13:22:08 +0000)

### Fixes

- Fixes delete of empty array

### Changes

- Updates code style

### New

- Get sorted array of hash table keys

## Release 0.6.12 - 2020-09-17(12:57:45 +0000)

### Changes

- Make timestamps more accurate  fill in the nanosecond field
- Documentation - clarify examples in "Setting Composite Values"

### New

- Make it possible to dump the content of a variant to the syslog

## Release 0.6.11 - 2020-09-03(05:13:31 +0000)

### Fixes

- Fixes g++ compilation warnings and errors

### Changes

- Add version prefix to support legacy build system

## Release 0.6.10 - 2020-09-01(19:34:50 +0000)

### Changes

- Add support for legacy tagging system with branch names in the tags
- Removes documentation generation jobs from the specific pipeline, they are now part of the default pipeline

## Release 0.6.9 - 2020-08-27(09:36:23 +0000)

### Changes

- Moves common re-usable macros to libamxc

## Release 0.6.8 - 2020-08-20(12:29:59 +0000)

### New

- Added amxc_string_is_numeric.

## Release 0.6.7 - 2020-08-14(21:31:27 +0000)

### Changes

- Improves hash table iterator `amxc_htable_for_each`, current iterator can be be (re)moved

## Release 0.6.6 - 2020-08-13(09:44:25 +0000)

### New 

-  variant list iterator macro
-  generic variant list join function

## Release 0.6.5 - 2020-08-04(04:55:03 +0000)

### Fixes

- Correct documentation tags

### Changes

- Update contributing guide

## Release 0.6.4 - 2020-07-24(10:58:59 +0000)

### Fixes

- Correctly add parts to linked list in string split functionality
- Make it possible to dump csv and ssv strings.
- Fixes taking amxc_string_t from variant

## Release 0.6.3 - 2020-07-22(18:05:43 +0000)

### Changes

- Adds RAW_VERSION to makefile.inc, VERSION must be X.Y.Z or X.Y.Z-HASH

## Release 0.6.2 - 2020-07-21(13:08:53 +0000)

### New

- String utility functions - resolve env variables and more

### Fixes

- Compilation issue with frotified musl

## Release 0.6.1 - 2020-07-15(13:45:56 +0000)

### New

- Adds amxc_string_copy function

## Release 0.6.0 - 2020-07-13(05:09:15 +0000)

### Changes

- String split and string join API's refactored and improved
- Update makefiles for SAH legacy build systems

## Release 0.5.5 - 2020-07-05(14:39:37 +0000)

### Fixes

- Memory leak in variant llist implementation and adds test

### Changes

- USes std=c11 instead of std=c18 for older compilers/toolchains

## Release 0.5.4 - 2020-07-01(20:04:43 +0000)

### Fixes

- `amxc_var_compare` results are wrong for some types

## Release 0.5.3 - 2020-06-30(07:45:20 +0000)

### Changes

- Scrubs Component.* files

## Release 0.5.2 - 2020-06-29(16:22:07 +0000)

### New 

- Support for legacy SAH build system

### Fixes

- Fixes compilation error with yocto & musl

## Release 0.5.1 - 2020-06-26(16:18:35 +0000)

### Fixes

- Fixes so name
- Fixes install target

## Release 0.5.0 - 2020-06-26(15:52:25 +0000)

### New 

- Variant type `csv_string` and `ssv_string`
- Copybara file

### Changes

- Builds targets into specific output directory

## Release 0.4.0 - 2020-06-19(10:53:02 +0000)

### New

- Timestamp data container
- Timestamp variant and conversions

### Changed

- Comma separate values string, splitting trims blanks from the individual parts

## Release 0.3.2 - 2020-06-15(11:02:26 +0000)

## New

- `amxc_variant_get_pathf` same as `amxc_var_get_path` but supports printf formatting for building path

## Release 0.3.1 - 2020-06-15(07:48:00 +0000)

### Fixes

- Issue #10 : comparing two empty string variants causes segmentation fault
- Adds tests to reproduce issue #10

### Changes

- update license to BSD+patent

## Release 0.3.0 - 2020-06-03(11:11:07 +0000)

### Changes

- Make it possible to delete current iterator from linked list while iterating over it using for_each macros (issue #9)
- Stops testing when test fails, preserve error code
- Collects unit test results

## Release 0.2.13 - 2020-05-28(06:36:19 +0000)

### Fixes

- Correct some typos in the documentation

## Release 0.2.12 - 2020-04-28(08:34:42 +0000)

### Fixes

- Returns empty string when string variant contains NULL string
- Crash when copying variant string containing NULL string
- Corrects documentation
- Fixes memory leak in test
- Fixes typo in documentation

## Release 0.2.11 - 2020-04-03(16:25:59 +0000)

### Fixes 

- Fixes amxc_string_prependf
- Fixes amxc_string_appendf - out of boundary bug

## Release 0.2.10 - 2020-04-01(17:51:34 +0000)

### Fixes

- Splitting string ending on separator string

## Release 0.2.9 - 2020-03-31(08:20:29 +0000)

### Changes

- API documentation - added documentation and fixes typos

## Release 0.2.8 - 2020-03-25(11:36:57 +0000)

### Changes

- Make var arg of function 'amxc_var_get_path' const

## Release 0.2.7 - 2020-03-11(06:26:56 +0000)

### Fixes

- Memory leak when adding duplicate keys to htable variant

## Release 0.2.6 - 2020-03-10(09:00:44 +0000)

### New

- variant types uint32_t and int32_t
- tests for new variant types
- Adds 'amxc_string_prependf' and 'amxc_string_vprependf' functions

### Changes

- Documentations generation configuration (doxygen)

## Release 0.2.5 - 2020-03-06(16:22:45 +0000)

### New

- Sortable linked list
- Linked list swap function
- amxc_string_vsetf, supports va_args

## Release 0.2.4 - 2020-03-01(15:14:23 +0000)

### New

- Feature - Sortable array
- API - new function `amxc_array_it_swap`
- API - new function `amxc_array_sort`

### Fixes

- DOC - doxygen documentation generation

### Changes

- CI/CD - Support ELK reporting
- CI/CD - Documentation generation
- CI/CD - Push HTML scan build and coverage reports to HTTP server

## Release 0.2.3 - 2020-02-22(21:40:08 +0000)

### Fixes

- Fixes issues found in analyses

### Changes

- Update .gitlab-ci.yml
- Corrects -Wl,-soname in linking, no version in soname

## Release 0.2.2 - 2020-02-19(12:59:11 +0000)

### Fixes

- Fix crash in amxc_var_take_amxc_string_t when variant contains NULL pointer
- Fix crash in amxc_string_delete

## Release 0.2.1 - 2020-02-18(10:30:37 +0000)

### New

- Linked lists and htable can be added to composite variant

## Changes

- Corrects documentation of function amxc_string_split_word_variant

## Release 0.2.0 - 2020-02-08(20:54:31 +0000)

### New

#### amxc_string_t

- adds 'amxc_string_setf' - resets amxc string and uses printf format to set the content
- adds 'amxc_string_appendf' - adds a string to an existing one using printf format
- adds 'amxc_string_join_variant_until' - joins parts into a string until a delimter is matched
- adds 'amxc_string_get_from_llist' - gets a string part (amxc_string_t) from a linked list
- adds 'amxc_string_get_text_from_llist' - gets a string part (const char *) from a linked list

#### amxc_var_t

- adds macro 'amxc_var_push' - resolves in amxc_var_push_<TYPE> functions
- adds 'amxc_var_take_amxc_string_t' - takes a amxc_string_t from variant (must be AMXC_VAR_ID_CSTRING)
- adds 'amxc_var_push_cstring_t' - pushes a 'char *' into a variant
- adds 'amxc_var_push_amxc_string_t' - pushes a 'amxc_string_t *' into a variant

### Changes

- renames function 'amxc_string_set_buffer' to 'amxc_string_push_buffer' (API consistency)
- do not strip binaries when installing (debugging feature)
- splitting a string in words keeps quotes in resulting list.

### Fixes

- amxc_string_new return value - int8_t -> int


## Release 0.2.0 - 2020-02-08(20:54:31 +0000)

### New

#### amxc_string_t

- adds 'amxc_string_setf' - resets amxc string and uses printf format to set the content
- adds 'amxc_string_appendf' - adds a string to an existing one using printf format
- adds 'amxc_string_join_variant_until' - joins parts into a string until a delimter is matched
- adds 'amxc_string_get_from_llist' - gets a string part (amxc_string_t) from a linked list
- adds 'amxc_string_get_text_from_llist' - gets a string part (const char *) from a linked list

#### amxc_var_t

- adds macro 'amxc_var_push' - resolves in amxc_var_push_<TYPE> functions
- adds 'amxc_var_take_amxc_string_t' - takes a amxc_string_t from variant (must be AMXC_VAR_ID_CSTRING)
- adds 'amxc_var_push_cstring_t' - pushes a 'char *' into a variant
- adds 'amxc_var_push_amxc_string_t' - pushes a 'amxc_string_t *' into a variant

### Changes

- renames function 'amxc_string_set_buffer' to 'amxc_string_push_buffer' (API consistency)
- do not strip binaries when installing (debugging feature)
- splitting a string in words keeps quotes in resulting list.

### Fixes

- amxc_string_new return value - int8_t -> int


## Release 0.1.4 - 2020-02-05(09:46:25 +0000)

## New

- Adds amxc_string_join_variant_until function

## Changes

- Gitlab CI/CD .gitlab-ci.yml change container image for building and testing

## Release 0.1.3 - 2020-02-03(06:50:04 +0000)

## New

- amxc_string_split functions
  - split string using separator into linked list of string or linked list of variants
  - split string into `words` into linked list of variants
- amxc_var_dump function
- wrapper functions to make it easier to add primitives into composite variant
- string take_buffer and set_buffer functions

## Fixes

- variant_htable and variant_list memory leaks, adds extra tests
- Adds set_buffer and take_buffer functions

## Release 0.1.2 - 2020-01-21(08:55:37 +0100)

### Fixes 

- variant type llist set index implementation
- gcc9.2 warning/error on strncpy 
- makefiles to accomodate archlinux pkgbuild
- improves & fixes set index implementation

### New

- variant type file descriptor

## Release 0.1.1 - 2020-01-15(13:30:02 +0000)

### New

- Adds trim functions and tests (issue 15)

## Release 0.1.0 - 2020-01-09(08:31:11 +0000)

### Fixes

- Added missing documentation (issue 17)
- Added missing tests (issue 18)
- Removed debug prints
- Fixed compilation errors (gcc 9.2.0)

### Documentation

- Removes common documents
- Updates links to common documents

### New

- Added fd variant implementation (issue 20)

## Release 0.0.9 - 2019-11-23(12:28:58 +0000)

### Fixes

- Code style
  - Fixes 13-assert-macros-assumes-exit-label-exists
  - Fixes all assert macros, label is passed as argument
  - Fixes typos in comment and change code layout

## Release 0.0.8 - 2019-11-16(15:24:15 +0000)

### Fixes

- issue 12 - Add AMXC_VAR_FLAG_UPDATE for amxc_var_set_index and amxc_var_set_key functions

## Release 0.0.7 - 2019-11-14(13:16:44 +0000)

### Added 

- `ANY` type for conversion functions
- `amxc_var_get_path` function - fetch from composed variant using dotted path

### Changed

- api changes - all getters (path,index,key) uses flag for copy or copyless

## Release 0.0.6 - 2019-11-10(19:57:26 +0000)

### Added

- `double` variant type
- Composed variants can be accessed by `key` or `index` using setters and getter functions
- Contribution guide - CONTRIBUTING.md
- Changelog - CHANGELOG.md

### Updated

- README.md
- Doxygen documentation
- Made code c18 compliant
