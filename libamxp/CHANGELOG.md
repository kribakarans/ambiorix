# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v2.0.0 - 2024-04-30(07:40:57 +0000)

### Other

- Avoid g++ compiler warning for new .add_value variant function pointer

## Release v1.4.2 - 2024-04-30(07:23:55 +0000)

### Other

- Fix typo in documentation

## Release v1.4.1 - 2024-04-18(16:59:27 +0000)

### Fixes

- Expose getter and eval binary expression tree functions

## Release v1.4.0 - 2024-02-01(15:17:32 +0000)

### New

- [AMX] Add ends with expression operator

## Release v1.3.2 - 2024-01-10(10:09:04 +0000)

### Fixes

- [WNC-CHR2][LCM] SoftwareModules cannot be found

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.3.1 - 2023-11-29(15:43:29 +0000)

### Fixes

- Update and extend documentation

## Release v1.3.0 - 2023-11-04(20:01:34 +0000)

### New

- Refactor libamxo - libamxp: move fd and connection management out of libamxo

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.2.12 - 2023-10-17(12:06:27 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.2.11 - 2023-10-12(10:15:14 +0000)

### Fixes

- [libamxp]Memory when parsing invalid list value

## Release v1.2.10 - 2023-10-09(05:50:19 +0000)

### Other

- Develop generic prpl voiceactivation module

## Release v1.2.9 - 2023-09-22(10:28:19 +0000)

### Fixes

- Fix license headers in files

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.2.8 - 2023-09-14(17:51:26 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.2.7 - 2023-09-08(09:39:14 +0000)

### Fixes

- amxp singal pipefds should be closed when spawning child processes

### Changes

- [libamxp]Scheduler api should be more tolerant regarding spaces in days of week list

## Release v1.2.6 - 2023-09-01(05:41:16 +0000)

### Fixes

- [libamxp] When enable or disable a scheduler it is possible that signals are not emitted or triggered

## Release v1.2.5 - 2023-07-25(06:22:23 +0000)

### Fixes

- Expression function contains should be able to use a list of values

## Release v1.2.4 - 2023-07-19(11:21:32 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.2.3 - 2023-06-27(09:35:03 +0000)

### Fixes

- Segmentation fault can occur when timers are added or deleted from within a timer callback

## Release v1.2.2 - 2023-06-20(07:58:21 +0000)

### Fixes

- When a schedule item is changed and is currently started send a stop event

## Release v1.2.1 - 2023-05-26(11:43:09 +0000)

### Fixes

- Scheduler does not take correct duration into account when multiple schedules expire at the same moment

## Release v1.2.0 - 2023-05-24(13:40:17 +0000)

### New

- [libamxp]Provide API for cron expression parsing and calculating next occurence

## Release v1.1.5 - 2023-05-10(08:44:52 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.1.4 - 2023-05-03(19:41:31 +0000)

### Fixes

- Check if htables are initialized

## Release v1.1.3 - 2023-04-21(16:22:59 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.1.2 - 2023-04-08(17:11:51 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v1.1.1 - 2023-03-17(13:13:20 +0000)

### Fixes

- Improvements in amxp regarding amxp_dir_scan, timer documentation and slot disconnects

## Release v1.1.0 - 2023-03-10(21:59:44 +0000)

### New

- [prpl][tr181-upnp] UPnP.Discovery and UPnP.Description are not implemented

## Release v1.0.3 - 2023-02-22(14:13:16 +0000)

### Fixes

- unbound does not start after reboot in tagged mode
- [CDROUTER][IPv6] Box sends 2 ICMPv6 RA when a RS is received on LAN

## Release v1.0.2 - 2023-02-16(10:00:42 +0000)

### Fixes

- [SSH][AMX] Processes spawned by dropbear instance managed SSH Manager ignores SIGINT

## Release v1.0.1 - 2023-02-13(11:51:03 +0000)

### Fixes

- Fix memory leakj wehn empty expression is used

## Release v1.0.0 - 2023-02-13(10:09:25 +0000)

### Breaking

- Improve logical expression parser

## Release v0.11.12 - 2023-01-30(16:48:13 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- unblock a signal when disabling it with amxp_syssig_enable

## Release v0.11.11 - 2023-01-11(20:16:58 +0000)

### Fixes

- 0-timeout timer postponed when starting another longer timer

## Release v0.11.10 - 2022-12-14(08:32:40 +0000)

### Fixes

- [multisettings] Using triggers is not effective

## Release v0.11.9 - 2022-12-06(13:44:24 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.11.8 - 2022-11-21(09:34:31 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.11.7 - 2022-11-19(11:57:19 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.11.6 - 2022-11-15(12:09:40 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.11.5 - 2022-11-14(07:19:50 +0000)

### Fixes

- Compile regular expressions and validate expressions only once
- Investigate and fix klocwork reports for ambiorix libs and tools

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.11.4 - 2022-11-03(11:09:45 +0000)

### Other

- Add ^= expression operator

## Release v0.11.3 - 2022-11-03(10:11:45 +0000)

### Other

- Add function to check if string is safe to build expressions with

## Release v0.11.2 - 2022-10-14(11:32:03 +0000)

## Release v0.11.1 - 2022-10-05(13:51:03 +0000)

### Fixes

- Apply change owner when uid or gid is different from zero

## Release v0.11.0 - 2022-10-05(12:00:54 +0000)

### New

- Add directory utility functions

### Fixes

- When signals are triggered in a recursive way it can lead to segfaults

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.10.6 - 2022-09-12(12:26:18 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.10.5 - 2022-08-29(07:18:59 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.10.4 - 2022-08-18(12:50:15 +0000)

### Changes

- [GL-B1300] Various components failing to open Service in firewall due to high load and multiple interface toggling

## Release v0.10.3 - 2022-08-17(08:30:11 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.10.2 - 2022-07-25(06:25:41 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.10.1 - 2022-06-01(11:53:37 +0000)

### Other

- [amx] crash on amxp signal read

## Release v0.10.0 - 2022-05-30(08:19:52 +0000)

### New

- It must be possible to suspend handling of signals for a specific signal manager

## Release v0.9.19 - 2022-05-23(10:46:30 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when...

## Release v0.9.18 - 2022-05-19(14:54:46 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.17 - 2022-04-25(08:07:44 +0000)

## Release v0.9.16 - 2022-04-06(09:28:45 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.15 - 2022-02-15(05:22:42 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.14 - 2022-02-04(14:45:07 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.13 - 2022-01-25(06:16:09 +0000)

### Fixes

- amxp_signal_has_slots only checks the first slot

## Release v0.9.12 - 2021-11-16(17:13:04 +0000)

## Release v0.9.11 - 2021-11-10(12:17:48 +0000)

### Changes

- When signal is deleted in slot, the remaining slots must be called
- Update dependencies in .gitlab-ci.yml

## Release v0.9.10 - 2021-10-28(21:48:41 +0000)

### Fixes

- Restarting timers can lead to early sigalrm

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.9 - 2021-10-20(18:25:18 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.8 - 2021-10-07(14:19:09 +0000)

### Changes

- Update implementation of ~= operator
- Update dependencies in .gitlab-ci.yml

## Release v0.9.7 - 2021-09-24(13:04:37 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.6 - 2021-09-23(09:11:47 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.5 - 2021-09-06(13:00:12 +0000)

### Fixes

- Disconnecting slots in slot callback function can lead to segmentation fault
- When child process is killed it stays in <defunc>

### Changes

- Adds support for bbf in operator ~=

### Other

- Generate junit xml files with unit-tests
- Issue: ambiorix/libraries/libamxp#36 Generate junit xml files with unit-tests

## Release v0.9.4 - 2021-08-23(10:09:45 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.3 - 2021-07-09(07:50:18 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.2 - 2021-07-02(18:24:24 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.1 - 2021-06-28(12:13:54 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.9.0 - 2021-06-21(07:07:18 +0000)

### New

- Make it possible to defer function calls

## Release v0.8.0 - 2021-06-18(16:06:10 +0000)

### New

- When using an amxc_set_t it must be possible to evaluate a flag expression with it

### Fixes

- Issue: 21 Deleting signal manager from callback function causes segmentation fault

### Changes

- Expressions with True or False should give matches

## Release v0.7.4 - 2021-06-08(08:15:41 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v0.7.3 - 2021-06-01(06:19:31 +0000)

## Release v0.7.2 - 2021-05-31(08:22:45 +0000)

### Changes

- Extend starts with compare operator for expressions

## Release v0.7.1 - 2021-05-21(10:57:14 +0000)

### Fixes

- Fix typos in amxp_subproc.h

## Release v0.7.0 - 2021-05-09(20:00:56 +0000)

### New

- Make it possible to use expressions in variant paths

## Release v0.6.12 - 2021-05-04(07:17:25 +0000)

### Changes

- Use common macros from libamxc

### Other

- Enable auto opensourcing

## Release v0.6.11 - 2021-04-23(18:23:33 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release 0.6.10 - 2021-04-15(19:51:58 +0000)

### Fixes

- Double free when deleting signal in slot callback function 

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 0.6.9 - 2021-04-08(20:09:23 +0000)

### Changes

- Move copybara to baf

## Release 0.6.8 - 2021-03-24(10:55:03 +0000)

### Fixes

- when right value of in comparator is a csv_string or a ssv_string they must function as an list

## Release 0.6.7 - 2021-03-10(10:47:03 +0000)

### Changes

- Step-up version of libamxc for CI

### New

- Process controller - launch and monitor child processes and track children
- Process info - fetch process information from /proc/<pid>/stat

### Fixes

- Blocks SIGINT for child processes

## Release 0.6.6 - 2021-02-25(13:18:49 +0000)

### Changes

-  Migrate to new licenses format (baf)

### Fixes

- Removing a signal from within a slot causes a segmentation fault

## Release 0.6.5 - 2021-02-14(07:46:39 +0000)

### Changes

- Step up version of libamxc for CI
- Add doxygen documentation to public API's

## Release 0.6.4 - 2021-01-28(08:22:46 +0000)

### Changes 

- Updates version of libamxc for Ci/CD pipelines

## Release 0.6.3 - 2021-01-18(14:28:30 +0000)

### New

- generate make files using build agnostic file (baf)

### Fixes

- Only include objects in static library

## Release 0.6.2 - 2021-01-04(11:16:08 +0000)

### Changes

- Step up libamxc version

### Fixes

- Check return value of fork systemcall

## Release 0.6.1 - 2020-11-30(15:15:22 +0000)

### Changes

- Updates makefiles

## Release 0.6.0 - 2020-11-29(15:35:22 +0000)

### New

- Adds move calback function to variant siginfo

### Changes

- Adds documentation for amxp_timer_t (doxygen)

## Release 0.5.4 - 2020-11-25(18:54:12 +0000)

### Changes

- Update readme

### Fixes

- Fix debian package dependencies

## Release 0.5.3 - 2020-11-16(10:55:31 +0000)

### Changes

- Adds documentation for expression API

## Release 0.5.2 - 2020-10-27(17:32:37 +0000)

### New 

- Adds bool function contains

### Fixes

- Checks if the get_field function is available

## Release 0.5.1 - 2020-10-19(18:45:51 +0000)

### Changes

- Step up version of libamxc to v0.7.2

## Release 0.5.0 - 2020-10-02(13:27:41 +0000)

### Changes

- Update code style

## Release 0.4.5 - 2020-09-17(13:16:27 +0000)

### Fixes

- Fixes parallel building

## Release v0.4.4 - 2020-09-03(13:45:17 +0000)

### Fixes

- pass version_prefix to make command

## Release v0.4.3 - 2020-09-03(05:45:17 +0000)

### Fixes

- Fixes g++ compilation warnings and errors

### Changes

- Add version prefix to support legacy build system

## Release 0.4.2 - 2020-08-20(12:39:41 +0000)

### Fixes

- set correct MAJOR number on libraries for internal builds

## Release 0.4.1 - 2020-08-16(09:02:34 +0000)

### Fixes

- Fixes issue #11 - segmentation fault in `amxp_sigmngr_trigger_signal`

## Release 0.4.0 - 2020-08-13(10:53:46 +0000)

### New

- Adds bool functions support
- Adds value functions support
- Adda support for lists in expressions
- Adds in comperator

### Changes

- Slots with different private data may connect

### Fixes

- Do not call functions when expression is being verified
- Solves most of the shift/reduce and reduce/reduce warnings

## Release 0.3.6 - 2020-08-03(06:17:09 +0000)

### Fixes

- Issue #8 - expression containing constants without comparison are invalid

### Changes

- Update contributing guide

## Release 0.3.5 - 2020-07-27(11:24:07 +0000)

### Changes

- Improves empty expression evaluation

## Release 0.3.4 - 2020-07-24(11:16:09 +0000)

### Changes

- Refactor the use of regular expressions

## Release 0.3.3 - 2020-07-22(18:27:42 +0000)

### Changes

- Adds RAW_VERSION to makefile.inc, VERSION must be X.Y.Z or X.Y.Z-HASH

### Fixes 

- Removes unused macros

## Release 0.3.2 - 2020-07-17(19:01:18 +0000)

### Changes

- Expression fields (Paths ) can start with a dot '.'

### Fixes

- Fixes memory leak, when unloading
- Fixes fortified compilation with musl

## Release 0.3.1 - 2020-07-13(05:20:18 +0000)

### Changes

- Update makefiles for SAH legacy build systems
- Updates API documentation

### Fixes

- amxp main header file
- Reset timerval to 0 when no active timers available

### New

- signal/slot documentation

## Release 0.3.0 - 2020-07-06(07:22:28 +0000)

### Changes

- Expression parser support for long text between quotes 
- Adds support for expression filtering when connecting to named signals

## Release 0.2.0 - 2020-07-05(15:03:09 +0000)

### New

- Logical expression parser and evaluator
- Logical expression evaluator status codes in enum

### Changes

- Slot filtering uses logical expression evaluator instead of regexp filtering
- Uses std=gnu11 instead of std=gnu18 to support older toolchains and compilers

## Release 0.1.15 - 2020-06-30(07:45:20 +0000)

### Changes

- Scrubs Component.* files

## Release 0.1.14 - 2020-06-29(16:22:08 +0000)

### New 

- Support for legacy SAH build system

## Release 0.1.13 - 2020-06-29(10:55:21 +0000)

### New 

- Timer implementation

## Release 0.1.12 - 2020-06-26(16:58:07 +0000)

### Changes

- Install libraries into target specific output directory

### New

- Copybara file

## Release 0.1.11 - 2020-06-16(10:50:51 +0000)

### Changes

- Update license to BSD+patent

## Release 0.1.10 - 2020-06-10(06:15:13 +0000)

### Fixes

- Triggers filtered slots when signal has no data

### New

- Unit test data collection for ELK

## Release 0.1.9 - 2020-05-28(06:29:32 +0000)

### New

- Makes it possible to disable signal handling of a signal manager
- Adds function `amxp_sigmngr_enable`

## Release 0.1.8 - 2020-05-27(08:02:30 +0000)

### Changes 

- Regexp matching for slots uses extended regexps

## Release 0.1.7 - 2020-04-03(16:39:31 +0000)

### Changes

- Trigger matching regexp slots when no signal with name is found

## Release 0.1.6 - 2020-03-31(08:31:42 +0000)

### New

- Slot filtering using regular expressions
- Slot connect using regular expression

### Update

- Documentation

## Release 0.1.5 - 2020-03-25(14:35:10 +0000)

### New

- Connect slots to signals using regular expression (Posix BRE)
- Trigger slots depending on filter on singal data (only composite variants)

## Release 0.1.4 - 2020-03-04(11:38:04 +0000)

### Changes

- Make it possible to create signal managers on the stack

## Release 0.1.3 - 2020-03-01(21:37:03 +0000)

### Changes

- DOC - doxygen documentation for signal and slots
- CI/CD - Support ELK reporting
- CI/CD - Documentation generation
- CI/CD - Push HTML scan build and coverage reports to HTTP server

### Fixes

- Subproc status and sigchild handling
- Fix reaping zombie processes using sigchld for complex multithreaded applications
- Fix include for Yocto compilation

## Release 0.1.2 - 2020-02-24(19:47:50 +0000)

### New

- subproc_wait functions and synchronous start wrappers
- tests for subproc_wait and synchronous start wrappers

### Changes

- makefile - add major version in so name
- exmaples

## Release 0.1.1 - 2020-02-24(10:43:37 +0000)

### Changes

- .gitignore - ignores core file from tests
- .gitlab-ci - use templates 
- makefile -Wl,-soname in linking, no version in soname

## Release 0.1.0 - 2020-02-18(10:47:08 +0000)

### Fixes

- Compiler error when building with yocto - use <sys/wait.h> instead of <wait.h>
- Test coverage - more tests added

### Changes

- README.md is updated
- Signal/slots - opaque handle cna be passed as private data to slots
- Example applications updated 

### New

- Function `amxp_sigmnr_find_signal`
- Function `amxp_signal_has_slots`

## Release 0.0.5 - 2020-01-21(08:19:18 +0000)

### Fixes

- Symbolic link in debian package
- Makefiles for archlinux pkgbuild support

## Release 0.0.4 - 2020-01-09(09:45:27 +0000)

### New

- Adds sub-process launcher and observer (child processes)
- System signals available through amxp signal/slot mechanism

### Changes

- Header file include clean-up

## Release 0.0.3 - 2019-11-24(21:29:34 +0000)

### Fixes

- Issue 3 signal improvements and refactoring

### Changes

- Make amxp_slot_t type private
- Removed dependency to amxj
- Use queue to asynchronous trigger signals (emit)
- Add (all) signal, make it possible to connect to all

## Release 0.0.2 - 2019-10-25(17:24:33 +0000)

### Fixes

- Debian packaging
  - Package name
  - Create symbolic link to so file in deb package

## Release 0.0.1 - 2019-10-19(16:29:17 +0000)

- observer pattern - signal & slot
