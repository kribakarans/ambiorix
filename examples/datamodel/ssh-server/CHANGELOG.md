# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v0.1.5 - 2022-05-23(16:29:16 +0000)

### Fixes

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when memory leaks are detected

## Release v0.1.4 - 2021-10-14(06:40:04 +0000)

## Release v0.1.3 - 2021-06-08(19:02:30 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components
- Updates readme, add underscores to ambiorix data model functions

## Release v0.1.2 - 2021-05-31(13:41:02 +0000)

- Disable cross-compilation

## Release 0.1.1 - 2021-04-15(20:56:56 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 0.1.0 - 2021-04-09(05:42:31 +0000)

### New

- Add uci storage through config sectio

### Changes

- Move copybara to baf

## Release 0.0.5 - 2021-03-27(10:21:19 +0000)

### Fixes

- [yocto] non -dev/-dbg/nativesdk- package contains symlink .so

## Release 0.0.4 - 2021-03-15(21:27:17 +0000)

### New

- Adds load and save functionality

### Changes

- Use `or` instead of `||` in expressions for SAH build system
- gitlab CI Updating sah buildsystem build files
- Disable print_event
- Updates readme
- Removes dropbear control implementation
- Use amxp_proc_info as fallback to get dropbear child processes

### Fixes

- Check status before launching dropbear

## Release 0.0.3 - 2021-03-01(18:12:08 +0000)

### Changes

- Update baf license
- Add copybara
- Updates readme - adds note about /proc/<pid>/task/<tid>/children and kernel versions

## Release 0.0.2 - 2021-02-28(19:41:05 +0000)

### New

- Unit tests

### Fixes

- Issues discovered with unit-test

## Release 0.0.1 - 2021-02-27(22:40:53 +0000)

### New

- Initial release
  - launch and stop dropbear
  - monitor dropbear child processes (sessions)
  - data model dropbear configuration  parameters
  - data model dropbear status parameters


