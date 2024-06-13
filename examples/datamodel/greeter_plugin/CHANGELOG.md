# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v0.4.5 - 2023-07-11(11:13:34 +0000)

### Changes

- [USP] GSDM should return whether commands are (a)sync

## Release v0.4.4 - 2023-01-19(13:58:59 +0000)

### Fixes

- Issue: unit-test failing - clean-up previous transaction before re-using the transaction object

## Release v0.4.3 - 2022-05-23(16:01:16 +0000)

### Other

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when...

## Release v0.4.2 - 2021-11-11(02:49:31 +0000)

## Release v0.4.1 - 2021-10-14(05:58:48 +0000)

## Release v0.4.0 - 2021-06-29(09:09:07 +0000)

### New

- Add a deferred RPC method example

## Release v0.3.2 - 2021-06-08(18:46:44 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

## Release v0.3.1 - 2021-05-31(13:19:30 +0000)

- Disable cross-compilation

## Release v0.3.0 - 2021-05-21(14:38:13 +0000)

### New

- Autogenerate data model documentation

## Release v0.2.14 - 2021-05-10(06:05:35 +0000)

### Changes

- Changes echo method
- Data model documentation must be added to the odls
- issue: #11 Use common macros from libamxc

### Other

- Enable auto opensourcing

## Release v0.2.13 - 2021-04-25(17:37:33 +0000)

### Changes

- Remove debug prints

## Release 0.2.12 - 2021-04-15(20:44:20 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 0.2.11 - 2021-04-09(05:42:07 +0000)

### Changes

- Move copybara to baf
- Update greeter stats actions

## Release 0.2.10 - 2021-04-01(08:11:03 +0000)

### Fixes

- Fixes segfault in reading statistics

## Release 0.2.9 - 2021-03-27(10:11:53 +0000)

### Fixes

- [yocto] non -dev/-dbg/nativesdk- package contains symlink .so

## Release 0.2.8 - 2021-03-15(21:16:53 +0000)

### Fixes

- Corrects makefile

## Release 0.2.7 - 2021-02-28(20:08:40 +0000)

### Changes

- Correct readme
- Migrate to new licenses format (baf)

## Release 0.2.6 - 2021-01-31(17:12:53 +0000)

### Fixes

- Fixes makefiles

## Release 0.2.5 - 2021-01-28(16:09:35 +0000)

### Changed

- README.md install instructions

### Fixes

- Incorrect installation of odl/greeter.odl

## Release 0.2.4 - 2021-01-19(12:18:52 +0000)

### New

- Auto generate make files using build agnostic file (baf)

## Release 0.2.3 - 2021-01-05(09:28:11 +0000)

### New

- Adds listen socket support
- CONTRIBUTION.md

### Changes

- More tests

## Release 0.2.2 - 2020-11-16(14:53:44 +0000)

### Changes

- Update gitlab CI/CD yml file
- Update README.md

## Release 0.2.1 - 2020-10-28(06:22:53 +0000)

### Changes 

- Clean-up main odl

## Release 0.2.0 - 2020-10-02(17:33:58 +0000)

### Changes

- Update code style

## Release 0.1.3 - 2020-09-18(05:54:55 +0000)

### New

- Configure PCB register name

### Fixes

- Update config options in greeter_extra.odl

## Release 0.1.2 - 2020-09-04(17:21:14 +0000)

### Fixes

- Fixes g++ warnings and errors, set correct compiler flags

## Release 0.1.1 - 2020-09-03(20:17:16 +0000)

### Fixes

- Fixes g++ warnings and errors, set correct compiler flags

## Release 0.1.0 - 2020-08-30(10:03:57 +0000)

### Changes

- Applies libamxd API changes
- Moved common macros to libamxc

## Release 0.0.3 - 2020-08-20(15:44:57 +0000)

### Changes

- Re-organized install target - this to support multiple start-up options

### Fixes

- Use transaction to change MaxHistory parameter

## Release 0.0.2 - 2020-08-14(14:23:35 +0000)

### New

- Tests

### Changes

- Updates documentation
- Move `echo` method in separate odl file
- Install greeter_extra.odl file

### Fixes 

- Fixes clean target
- Tests artifacts must be ignored
- Object paths in event subscriptions must contain an leading dot

## Release 0.0.1 - 2020-07-29(11:38:49 +0000)

### New

- Initial data model example, showing a bunch of features
- Example explained/documented in README.md

