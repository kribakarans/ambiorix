# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v1.2.1 - 2023-10-12(16:30:37 +0000)

### Fixes

- Fix license headers in files

## Release v1.2.0 - 2022-05-03(11:07:13 +0000)

### New

- Check get_instances function of back-end

## Release v1.1.1 - 2021-10-29(05:13:41 +0000)

## Release v1.1.0 - 2021-10-13(12:34:51 +0000)

### New

- amxb inspect must verify functions `has` and `capabilities`

## Release v1.0.6 - 2021-07-22(12:21:36 +0000)

### Changes

- amxb-inspect must verify wait_for function

## Release v1.0.5 - 2021-06-28(14:18:18 +0000)

### Fixes

- make clean does not clean the output directory

## Release v1.0.4 - 2021-06-09(14:29:15 +0000)

- Enable auto-opensourcing

## Release v1.0.3 - 2021-06-08(17:59:22 +0000)

## Release 1.0.2 - 2021-04-16(11:14:37 +0000)

## Release 1.0.1 - 2021-04-15(20:20:09 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 1.0.0 - 2021-04-08(22:09:29 +0000)

### Changes

- Move copybara to baf

## Release 0.3.0 - 2021-02-26(18:02:34 +0000)

### New 

- Check if read-raw is available

### Changes

- Migrate to new licenses format (baf)

## Release 0.2.1 - 2021-01-19(07:51:49 +0000)

### New

- Auto generate make files using build agnostic file (baf)

## Release 0.2.0 - 2021-01-08(17:59:48 +0000)

### New

- Add contributing.md

### Changes

- Adds function verification (listen, accept, list)

## Release 0.1.3 - 2020-11-29(18:49:30 +0000)

### Changes

- Update readme

### Fixes

- Fix debian package dependencies

## Release 0.1.2 - 2020-11-16(14:36:58 +0000)

### Changes

- Update gitlab CI/CD yml file

## Release 0.1.1 - 2020-11-03(07:37:10 +0000)

### Changes

- Check describe function

## Release 0.1.0 - 2020-10-02(17:03:02 +0000)

### Changes

- Update code style

## Release 0.0.8 - 2020-09-18(05:39:01 +0000)

### New

- Adds check for get_supported and set_config funtions

## Release 0.0.7 - 2020-09-04(16:59:42 +0000)

### Fixes

- Fixes g++ compiler warnings and errors

## Release 0.0.6 - 2020-08-22(16:17:55 +0000)

### New

- Checks if back-end has basic data model operator functions

## Release 0.0.5 - 2020-07-29(10:13:34 +0000)

### Fixes

- Version checking min and max supported
- Version parsing in makefile
- Compilation issue with frotified musl

### Changes

- Adds RAW_VERSION to makefile.inc, VERSION must be X.Y.Z or X.Y.Z-HASH

## Release 0.0.4 - 2020-07-06(09:27:14 +0000)

### Changes

- Uses std=c11 instead of std=c18, to support older toolchains and compilers

## Release 0.0.3 - 2020-06-30(08:33:39 +0000)

### New

- Add copybara file

### Changes

- update license to BSD+patent

## Release 0.0.2 - 2020-05-24(08:54:26 +0000)

### Changes

- Uses default pipeline
- Adds build dependency
- Adds unrustify 

## Release 0.0.1 - 2020-02-27(10:14:30 +0000)

### Changes

- Fixes sigemptyset and sigaction, use correct POSIX version (_GNU_SOURCE)
- Adds package creation
