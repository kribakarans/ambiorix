# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v2.1.3 - 2023-12-08(14:38:16 +0000)

### Fixes

- Fix the linker again, errors were still encountered with the previous one

## Release v2.1.2 - 2023-10-31(09:29:51 +0000)

### Fixes

- [AMX] libamxo linker issue

## Release v2.1.1 - 2023-10-12(12:59:40 +0000)

### Fixes

- Fix license headers in files

## Release v2.1.0 - 2023-08-23(07:40:37 +0000)

### New

- Use new AMXRT prefixed macros

## Release v2.0.3 - 2023-07-13(14:27:20 +0000)

## Release v2.0.2 - 2023-07-13(13:47:46 +0000)

## Release v2.0.1 - 2023-07-11(09:11:56 +0000)

## Release v2.0.0 - 2023-06-27(14:16:36 +0000)

### New

- use libamxrt

## Release v1.5.20 - 2023-05-25(06:00:31 +0000)

## Release v1.5.19 - 2023-05-24(17:59:06 +0000)

## Release v1.5.18 - 2023-05-10(13:40:44 +0000)

### Other

- Create the voice interface between ubus and pcb (tr104i1/2 mapper)

## Release v1.5.17 - 2023-03-30(19:53:20 +0000)

### Fixes

- Listen socket connections are not removed from the event loop

## Release v1.5.16 - 2023-03-13(09:54:47 +0000)

## Release v1.5.15 - 2023-02-28(10:17:21 +0000)

### Fixes

- Can write event must only be created once

## Release v1.5.14 - 2023-01-31(06:47:25 +0000)

### Fixes

- [MQTT][USP] Overlapping reconnects can cause a segmentation fault

## Release v1.5.13 - 2022-12-14(11:01:13 +0000)

### Fixes

- [amxrt] el_slot_wait_write_fd is added to late to signal `connection-wait-write`

## Release v1.5.12 - 2022-12-07(09:07:14 +0000)

## Release v1.5.11 - 2022-11-03(14:01:11 +0000)

### Other

- Implement reboot/upgrade persistence for Ambiorix objects

## Release v1.5.10 - 2022-10-07(11:34:48 +0000)

### Changes

- Use amxp functions for creating and scanning directories

## Release v1.5.9 - 2022-09-27(12:30:42 +0000)

### Changes

- Auto detect usp sockets

## Release v1.5.8 - 2022-09-12(14:44:27 +0000)

### Changes

- [USP] Location of odl save files needs to change

## Release v1.5.7 - 2022-08-05(10:14:19 +0000)

### Fixes

- amxrt fails to create folder

## Release v1.5.6 - 2022-07-27(09:08:47 +0000)

## Release v1.5.5 - 2022-07-05(19:06:39 +0000)

### Fixes

- Plugins not starting at boot

## Release v1.5.4 - 2022-07-04(14:29:38 +0000)

### Fixes

- Changes for hop-1509 causes regressions

## Release v1.5.3 - 2022-06-28(11:42:46 +0000)

### Fixes

- When amxrt is stopped while waiting for required objects the entrypoints should not be called with reason STOP

## Release v1.5.2 - 2022-06-15(10:46:26 +0000)

### Changes

- Plugins not starting at boot

## Release v1.5.1 - 2022-06-09(15:59:34 +0000)

### Fixes

- Load order must be the same as save order

## Release v1.5.0 - 2022-06-01(13:27:25 +0000)

### New

- When there are required objects events can appear before the entry points are called

## Release v1.4.4 - 2022-02-18(10:22:24 +0000)

### Fixes

- Plug-in name is not correctly passed to pcb back-end

## Release v1.4.3 - 2022-02-17(09:30:00 +0000)

### Fixes

- Link amxrt with libyajl

## Release v1.4.2 - 2022-02-17(08:12:39 +0000)

### Fixes

- Adds yajl as dependency in baf

## Release v1.4.1 - 2022-02-16(13:27:30 +0000)

### Fixes

- Fixes regression

## Release v1.4.0 - 2022-02-16(08:01:56 +0000)

### New

- Commandline options -o and -F must support configuration paths and json data

## Release v1.3.3 - 2021-12-08(14:20:23 +0000)

### Changes

- Make it possible to handle data model events before app:start event is triggered

## Release v1.3.2 - 2021-11-16(20:16:10 +0000)

## Release v1.3.1 - 2021-11-10(19:08:52 +0000)

### Fixes

- Fixes compilation issue for g++

## Release v1.3.0 - 2021-10-29(04:41:44 +0000)

### New

- It must be possible to connect to uris without registering a data model

## Release v1.2.0 - 2021-10-20(19:32:50 +0000)

### New

- Listen to signals that indicate a wait-for-write fd must be added to the event loop

## Release v1.1.6 - 2021-10-13(11:56:50 +0000)

## Release v1.1.5 - 2021-09-23(13:30:15 +0000)

### Other

- Issue: ambiorix/applications/amxrt#34 Make sure eventing is enabled before entry-points are called

## Release v1.1.4 - 2021-09-23(12:21:37 +0000)

### Fixes

- When using auto load with events turned off objects are not registered to bus

## Release v1.1.3 - 2021-07-27(07:28:57 +0000)

### Changes

- Adds simple rbus autodoetect socket

## Release v1.1.2 - 2021-07-23(17:27:23 +0000)

## Release v1.1.1 - 2021-07-22(12:03:34 +0000)

### Changes

- Improve save functionality in amxrt

## Release v1.1.0 - 2021-07-12(08:40:47 +0000)

### New

- Updates run-time to have support for wait-for-objects feature

## Release v1.0.5 - 2021-06-28(13:53:47 +0000)

## Release v1.0.4 - 2021-06-19(05:52:55 +0000)

### Fixes

- ODL config option dm-eventing-enabled has no effect when changed in the odl file

### Changes

- Use command line option -o to override ODL config options

## Release v1.0.3 - 2021-06-08(09:38:36 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

## Release 1.0.2 - 2021-04-15(20:17:00 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 1.0.1 - 2021-04-15(11:08:25 +0000)

### Fixes

- VERSION_PREFIX is needed in buildfiles 
- When one of the entry-points fail at startup all of them must be called when exiting 

### Changes

- Update readme 

## Release 1.0.0 - 2021-04-08(21:56:10 +0000)

### New

- It must be possible to save a data model in an automatic manner

### Changes

- Move copybara to baf

## Release 0.4.5 - 2021-03-31(14:07:17 +0000)

### Changes

- Calls entry-points in reverse order when stopping

## Release 0.4.4 - 2021-03-27(09:56:56 +0000)

### Changes

- Update baf to integrate new license generation

## Release 0.4.3 - 2021-03-15(20:43:32 +0000)

### Fixes

- .gitignore - ingores version.h

## Release 0.4.2 - 2021-03-12(10:55:47 +0000)

### Fixes

- When auto-detect is set all back-ends in back-end dir should be loaded

## Release 0.4.1 - 2021-03-11(06:34:55 +0000)

### Changes

- Removes artifacts and updates gitignore
- Add more command line start-up options

## Release 0.4.0 - 2021-02-26(17:49:34 +0000)

### New

- Add the possibility to enable system signals through eventloop
- Runtime must call the entry points with reason AMXO_ODL_LOADED (2) when post include files are loaded

### Changes

- Migrate to new licenses format (baf)

## Release 0.3.3 - 2021-01-31(21:09:25 +0000)

### Fixes

- amxrt should not exit when there are still open listen sockets

## Release 0.3.2 - 2021-01-28(10:42:17 +0000)

### Changes

- Rename configuration variable to original name

### Fixes

- Compiling amxrt failes sometimes when it is not linked explicitly with liburiparser
- Fixes installation target

## Release 0.3.1 - 2021-01-19(07:45:28 +0000)

### New

- Auto generate make files using build agnostic file (baf)

## Release 0.3.0 - 2021-01-08(17:50:44 +0000)

### New

- Support ofr listen sockets
- Unit tests
- Contributing.md file

## Release 0.2.4 - 2020-11-30(17:07:05 +0000)

### Changes

- Update makefile

## Release 0.2.3 - 2020-11-20(19:13:01 +0000)

### Fixes

- Fixes makefiles

### Changes

- Update readme
- Adds introduction to readme

## Release 0.2.2 - 2020-11-16(13:42:44 +0000)

### Changes

- Update gitlab CI/CD yml file

### Fixes

- ubus.sock directory changed

## Release 0.2.1 - 2020-10-28(06:06:39 +0000)

### New

- Scan mib dir at start-up

### Changes

- Add default directories to config options

### Fixes

- Only removes bus connection contexts


## Release 0.2.0-5-g0c08559 - 2020-10-28(06:06:35 +0000)

- Merge branch '9-add-default-directories-to-config-options' into 'master'
- Adds scan mib dir
- Add default directories to config options
- Adds default directories to parser config
- Only removes bus connection contexts

## Release 0.2.0 - 2020-10-02(16:32:58 +0000)

### Changes

- Update code style

## Release 0.1.3 - 2020-09-17(21:15:36 +0000)

### New 

- Pass config options to the bus back-ends

### Fixes 

- reports wrong pid in pid file.
- Creation of a pid-file must be enabled by default
- Pid-file creation enabled by default, command line opt-out option available

## Release 0.1.2 - 2020-09-03(16:12:38 +0000)

### Fixes

- Fixes g++ compilation warnings and errors

## Release 0.1.0 - 2020-08-30(08:08:58 +0000)

### Changes

- Common macros moved to libamxc

## Release 0.0.9 - 2020-08-20(14:00:59 +0000)

### Fixes

- set correct MAJOR number on libraries for internal builds
- Remove socket from el when remote end closes, stop application when no more connections available

### New

- Add the possibility to create a pid file
- Extra config options, which can be set using env vars as well

## Release 0.0.8 - 2020-07-29(10:23:56 +0000)

### Changes

- Adds RAW_VERSION to makefile.inc, VERSION must be X.Y.Z or X.Y.Z-HASH

### Fixes

- Compilation issue with fortified musl

## Release 0.0.7 - 2020-07-13(07:11:04 +0000)

### Fixes

- Updates code for string_split API changes

## Release 0.0.6 - 2020-07-06(08:25:31 +0000)

### Changes

- Applies API changes (amxp_slot_connect)

## Release 0.0.5 - 2020-07-05(18:55:41 +0000)

### Changes

- Uses std=c11 instead of std=c18, to support older toolchains and compilers

### Fixes 

- Fixes memory leak in timer support

## Release 0.0.4 - 2020-06-30(08:33:39 +0000)

### New

- Add copybara file
- Add timer support in eventloop

## Release 0.0.3 - 2020-06-16(13:32:59 +0000)

### Changed

- Makes sure data model is available before calling entry points
- Adds connection type indication
- Updates license to BSD+patent

### New

- Sigterm is correctly handled
- Triggers signals app:start and app:stop

## Release 0.0.2 - 2020-06-08(08:56:49 +0000)

### Fixes

- Install target, Removes strip (yocto)

## Release 0.0.1 - 2020-05-21(10:14:30 +0000)

### Changes

- Initial version
