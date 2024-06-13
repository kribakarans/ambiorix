# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v0.11.3 - 2024-03-18(12:59:32 +0000)

### Other

- [ba-cli]When set fails the error must be printed instead of no data found

## Release v0.11.2 - 2024-02-22(17:30:30 +0000)

### Other

- [ba-cli] "ubus-protected" not working anymore

## Release v0.11.1 - 2024-02-13(09:22:32 +0000)

### Other

- [ba-cli]ba-cli should connect to all available bus systems

## Release v0.11.0 - 2024-02-06(09:19:29 +0000)

### Other

- [cli]It must be possible to connect to ipv6 lla

## Release v0.10.0 - 2024-01-29(13:36:45 +0000)

### Other

- [amx][cli] Add syntax to filter parameters list

## Release v0.9.4 - 2024-01-11(09:05:24 +0000)

### Fixes

- [amx-cli] Allow proper escaping of variable in cli for input and display

## Release v0.9.3 - 2023-12-11(11:35:53 +0000)

### Fixes

- [ba-cli] bus URIs duplicated

## Release v0.9.2 - 2023-12-07(11:30:17 +0000)

### Fixes

- Update ba-cli bus commands documentation

## Release v0.9.1 - 2023-12-06(15:23:57 +0000)

### Changes

- Add and update documentation

## Release v0.9.0 - 2023-11-30(06:11:12 +0000)

### New

- Add posibility for action handlers to provide a description

## Release v0.8.25 - 2023-11-18(18:57:40 +0000)

### Changes

- Add timestamp for events printed in AMX CLI

## Release v0.8.24 - 2023-11-14(19:10:04 +0000)

### Fixes

- Wifi NOK on Safran prpl mainline

## Release v0.8.23 - 2023-11-09(10:23:09 +0000)

### Fixes

- [amx-cli]Completion on empty or root object is not working when using multiple connections

## Release v0.8.22 - 2023-11-08(10:16:44 +0000)

### Fixes

- [amx-cli]Completion on empty or root object is not working when using multiple connections

## Release v0.8.21 - 2023-11-06(11:18:57 +0000)

## Release v0.8.20 - 2023-11-06(11:00:41 +0000)

### Changes

- Refactor libamxo - libamxp: move fd and connection management out of libamxo

## Release v0.8.19 - 2023-10-30(17:14:07 +0000)

### Fixes

- [amx-cli]List doesn't provide output when redirected to file

## Release v0.8.18 - 2023-10-25(07:58:11 +0000)

### Changes

- Extend help of get command `?`

## Release v0.8.17 - 2023-10-18(06:22:03 +0000)

## Release v0.8.16 - 2023-10-18(05:13:17 +0000)

### Changes

- [mod-ba-cli]The cli is always resolving environment variables and configuration variables

## Release v0.8.15 - 2023-10-13(05:45:46 +0000)

### Fixes

- Fix license headers in files

## Release v0.8.14 - 2023-10-09(12:40:23 +0000)

### Fixes

- It must be possible to call native ubus object methods

## Release v0.8.13 - 2023-09-01(08:11:28 +0000)

## Release v0.8.12 - 2023-08-18(13:25:36 +0000)

### Fixes

- Memory leak in ba-cli with auto-connect functionality

## Release v0.8.11 - 2023-07-28(07:40:29 +0000)

### Fixes

- [ba-cli] output in 10s when ba-cli query invoked from console

## Release v0.8.10 - 2023-07-25(15:56:24 +0000)

### Fixes

- bus agnostic cli must be able to auto detect backends and sockets

## Release v0.8.9 - 2023-07-25(09:41:36 +0000)

### Fixes

- bus agnostic cli must be able to auto detect backends and sockets

## Release v0.8.8 - 2023-07-11(10:05:44 +0000)

### Changes

- [USP] GSDM should return whether commands are (a)sync

## Release v0.8.7 - 2023-06-28(17:10:32 +0000)

### Changes

- Add requests with search paths are allowed

## Release v0.8.6 - 2023-06-20(18:09:57 +0000)

### Fixes

- Remove destructor and use exit function

## Release v0.8.5 - 2023-05-24(19:03:24 +0000)

### Fixes

- [AMX] Get instances supports search paths

## Release v0.8.4 - 2023-05-03(09:05:13 +0000)

### Fixes

- gsdm missing arguments for commands and events

## Release v0.8.3 - 2023-04-03(12:21:23 +0000)

### Fixes

- [Ambiorix] Implement function call with search path

## Release v0.8.2 - 2023-03-31(11:16:42 +0000)

## Release v0.8.1 - 2023-02-22(18:27:59 +0000)

## Release v0.8.0 - 2023-02-17(06:58:32 +0000)

### New

- Add json output format to cli (ubus-cli, pcb-cli, ba-cli)

## Release v0.7.17 - 2023-02-16(12:50:30 +0000)

### Fixes

- When asking a parameter value in the cli, it returns more than expected.

## Release v0.7.16 - 2023-02-13(22:07:34 +0000)

## Release v0.7.15 - 2023-02-13(17:57:26 +0000)

## Release v0.7.14 - 2023-02-13(17:47:47 +0000)

### Changes

- Replace openwrt ASCII art by prplOS one

## Release v0.7.13 - 2023-01-31(08:08:57 +0000)

## Release v0.7.12 - 2023-01-12(07:46:39 +0000)

### Fixes

- [AMX] ACL directory must be updated for mod-ba-cli

## Release v0.7.11 - 2022-11-28(14:10:29 +0000)

### Fixes

- Fix wrong usage of function amxd_path_setf

## Release v0.7.10 - 2022-11-14(10:15:56 +0000)

### Changes

- [AMX] Dump output arguments of failed methods

## Release v0.7.9 - 2022-10-20(17:13:40 +0000)

### Fixes

- Wrong configuration is passed to back-ends when connecting

## Release v0.7.8 - 2022-10-14(06:20:03 +0000)

### Other

- [USP][CDROUTER] GetSupportedDM on Device.LocalAgent. using a single object, first_level_only true, all options presents no event

## Release v0.7.7 - 2022-09-22(08:48:56 +0000)

### Changes

- [USP] Add requests with search paths will be allowed

## Release v0.7.6 - 2022-08-29(11:01:13 +0000)

### Changes

- Set config variant before connecting to back-end

## Release v0.7.5 - 2022-06-22(09:32:46 +0000)

### Changes

- Dump command must display mutable attribute when set

## Release v0.7.4 - 2022-06-10(06:59:57 +0000)

### Fixes

- Issue: # 19 Pcb and ubus config files should be installed by default

## Release v0.7.3 - 2022-05-23(15:25:32 +0000)

### Other

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when...
- Use amxa_get to avoid code duplications

## Release v0.7.2 - 2022-05-12(14:17:23 +0000)

### Changes

- [Ambiorix] Implementation of reference following decorator

## Release v0.7.1 - 2022-05-05(16:08:02 +0000)

### Other

- Issue: ambiorix/modules/amx_cli/mod-ba-cli#18 Update output of gsdm command [changed]

## Release v0.7.0 - 2022-05-03(11:45:18 +0000)

### New

- Add get instances command

## Release v0.6.0 - 2022-02-03(21:26:43 +0000)

### New

- It must be possible to show and access protected Parameters/Objects.

## Release v0.5.1 - 2022-01-25(12:59:39 +0000)

### Fixes

- Revert set partial option

## Release v0.5.0 - 2021-12-16(11:10:30 +0000)

### New

- Make it possible to do partial set

## Release v0.4.1 - 2021-11-30(12:19:54 +0000)

### Changes

- Code clean-up

## Release v0.4.0 - 2021-10-29(06:08:31 +0000)

### New

- [CLI][AMX] Add support for ACLs in the cli

## Release v0.3.8 - 2021-10-14(05:39:06 +0000)

## Release v0.3.7 - 2021-10-05(09:38:06 +0000)

### Fixes

- Fixes acl get verification

## Release v0.3.6 - 2021-09-27(11:58:52 +0000)

### Changes

- Add acl verification for get

## Release v0.3.5 - 2021-08-06(15:27:32 +0000)

### Fixes

- Missing symlinks to /usr/bin/amx-cli on installation of the debian package

## Release v0.3.4 - 2021-07-27(08:28:22 +0000)

### Fixes

- It must be possible to provide composite values to method arguments

## Release v0.3.3 - 2021-06-29(08:39:40 +0000)

### Changes

- Make it possible to push bus or backend specific configuration

### Other

- Enable auto opensourcing

## Release v0.3.2 - 2021-06-21(14:44:00 +0000)

### Changes

- Issue #10 Invoking data model methods must be done asynchronously

## Release v0.3.1 - 2021-06-11(07:26:34 +0000)

## Release v0.3.0 - 2021-06-11(07:15:15 +0000)

### New

- Add get supported data model command

### Changes

- When a get request returns an empty data set a message must be printed

## Release v0.2.1 - 2021-06-08(18:31:26 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

## Release v0.2.0 - 2021-06-02(12:51:37 +0000)

### New

- Add resolve command
- Adds who has cmd to connections

### Fixes

- It must be possible to subscribe for events using a search path

### Changes

- Use new subscription API

## Release v0.1.0 - 2021-05-09(21:27:38 +0000)

### New

- Component should have a debian package

### Changes

- Use common macros from libamxc

## Release v0.0.6 - 2021-04-25(18:08:30 +0000)

### Fixes

- When no instances are deleted the cli does not provide feedback

## Release v0.0.5 - 2021-04-21(10:39:33 +0000)

### Changes

- Updates dump help text

## Release 0.0.4 - 2021-04-15(20:23:17 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 0.0.3 - 2021-04-15(11:12:07 +0000)

## Release 0.0.2 - 2021-04-14(13:34:49 +0000)

### Fixes

- Add ubus and pcb specific configuration and symlinks 

