# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v0.2.21 - 2023-05-24(20:08:21 +0000)

## Release v0.2.20 - 2022-05-23(16:21:48 +0000)

### Fixes

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when memory leaks are detected

## Release v0.2.19 - 2022-02-16(20:05:06 +0000)

## Release v0.2.18 - 2022-01-25(14:44:21 +0000)

### Fixes

- Sleep in unit test can be too short

## Release v0.2.17 - 2021-10-14(06:20:53 +0000)

## Release v0.2.16 - 2021-08-24(13:57:33 +0000)

### Changes

- Correct example start-up in README.md

## Release v0.2.15 - 2021-06-29(09:20:40 +0000)

### Fixes

- Missing description in baf file

## Release v0.2.14 - 2021-06-08(18:58:09 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

## Release v0.2.13 - 2021-05-31(13:32:52 +0000)

- Disable cross-compilation

## Release v0.2.12 - 2021-05-21(14:54:45 +0000)

### Changes

- Re-enable tests

### Other

- Enable auto opensourcing

## Release 0.2.11 - 2021-04-15(20:53:40 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 0.2.10 - 2021-04-09(05:42:56 +0000)

### Changes

- Move copybara to baf

## Release 0.2.9 - 2021-03-27(10:15:13 +0000)

### Fixes

- [yocto] non -dev/-dbg/nativesdk- package contains symlink .so

## Release 0.2.8 - 2021-02-28(21:00:04 +0000)

### Changes

- Adds tests
- Migrate to new licenses format (baf)

## Release 0.2.7 - 2021-02-14(18:34:20 +0000)

### Fixes

- Check reason code in validation function

## Release 0.2.6 - 2021-01-28(16:54:19 +0000)

### Changes

- README.md - install instructions

## Release 0.2.5 - 2021-01-19(19:12:09 +0000)

### New

- Auto generate make files using build agnostic file (baf)

### Changes

- Rename to amx-tr181-localagent-threshold

## Release 0.2.4 - 2021-01-09(12:21:52 +0000)

### New

- CONTRIBUTION.md added

### Fixes

- Fixes tests (api changes)
- Fixes makefile.inc

## Release 0.2.3 - 2020-11-29(19:43:13 +0000)

### Changes

- Update copy.bara.sky

## Release 0.2.2 - 2020-11-16(15:04:27 +0000)

### Changes

- Update gitlab CI/CD yml file

## Release 0.2.1 - 2020-10-28(06:57:22 +0000)

### Changes

- Change install dirs and clean-up odl files

## Release 0.2.0 - 2020-10-02(20:17:23 +0000)

### Changes

- Update code style

## Release 0.1.3 - 2020-09-18(06:02:13 +0000)

### Changes

- Adds PCB register name in configuration

## Release 0.1.2 - 2020-09-04(17:33:36 +0000)

### Fixes

- Fixes makefiles

## Release 0.1.1 - 2020-09-03(20:36:48 +0000)

### Fixes

- Fixes g++ compilation warnings and errors

## Release 0.1.0 - 2020-08-30(10:08:53 +0000)

### Changes

- Applies libamxd API changes
- Uses macros to fetch data from variant hash table

## Release 0.0.4 - 2020-08-23(20:29:16 +0000)

### Changes

- Updates readme.md
- Use standard parameter validate action check_is_in

## Release 0.0.3 - 2020-08-21(19:42:27 +0000)

### Changes

- Updates code for API change

## Release 0.0.2 - 2020-08-20(15:50:37 +0000)

### Changes

- Re-organized install target - this to support multiple start-up options
- Moves dummy backend for testing to common dir
- Re-organize event testing

### Fixes

- Updates expression builder, do not use search_path function if path is not a search_path
- Fixes TOC of README.md

## Release 0.0.1 - 2020-08-16(15:00:08 +0000)

### New

- Initial version - see README.md
