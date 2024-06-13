# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v3.10.1 - 2024-03-20(10:17:10 +0000)

### Fixes

- [AMX] Eventing no longer works for mapped native pcb objects

## Release v3.10.0 - 2024-03-15(13:24:09 +0000)

### Other

- After reboot all hosts are disconnected (AKA amb timeouts)

## Release v3.9.7 - 2024-02-28(12:24:23 +0000)

### Fixes

- Do not create a subscription if an object is found and the notify flags are not set

## Release v3.9.6 - 2024-02-23(12:45:28 +0000)

### Other

- [PCB] Add parameter_not_found error code

## Release v3.9.5 - 2024-02-19(11:52:01 +0000)

### Other

- uspagent -D crash

## Release v3.9.4 - 2024-02-19(09:15:07 +0000)

### Fixes

- Crash in tr181-device

## Release v3.9.3 - 2024-02-13(09:21:57 +0000)

### Fixes

- Fix a memory growth

## Release v3.9.2 - 2024-01-31(11:18:33 +0000)

### Other

- [ba-cli] Events are not showed when requested using pcb-cli with gsdm command

## Release v3.9.1 - 2024-01-29(17:03:25 +0000)

### Other

- [amx][cli] Add syntax to filter parameters list

## Release v3.9.0 - 2024-01-29(13:36:03 +0000)

### Other

- [amx][cli] Add syntax to filter parameters list

## Release v3.8.0 - 2024-01-18(21:06:20 +0000)

### Fixes

- Problems with getdebug on Nokia prpl mainline

### Changes

- Problems with getdebug on Nokia prpl mainline
- [AMX_PCB] subscribing before creating object, do not get events.

## Release v3.7.1 - 2024-01-13(10:45:26 +0000)

### Fixes

- Error codes are lost when using the pcb mapper

## Release v3.7.0 - 2024-01-13(10:40:09 +0000)

### Fixes

- [PCB Backend] Incoming requests are handled while waiting for a response
- [amx]Datamodels accessed through pcb must respect the pcb notification request flags

### Changes

- [amx]Datamodels accessed through pcb must respect the pcb notification request flags
- Update dependencies in .gitlab-ci.yml

## Release v3.6.33 - 2023-12-13(06:54:49 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.32 - 2023-12-12(20:33:41 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.31 - 2023-12-12(18:30:09 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.30 - 2023-12-06(15:03:27 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.29 - 2023-11-29(19:43:40 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.28 - 2023-11-21(20:17:59 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.27 - 2023-11-18(18:17:01 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.26 - 2023-11-14(18:58:38 +0000)

### Fixes

- Full objects are replied when it is not needed
- [DataModel][TR-181]"Device.DeviceInfo.VendorConfigFile.Date" parameter type Not as expected

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- [USP] [Add_msg] Wrong error code in the response when a Add message is requested with an invalid parameter or value.

## Release v3.6.25 - 2023-11-06(10:49:43 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.24 - 2023-10-30(17:05:49 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.23 - 2023-10-25(07:49:20 +0000)

### Fixes

- pcb_cli parameter query returns error when query-ing amx parameter

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.22 - 2023-10-19(18:33:37 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.21 - 2023-10-17(22:08:22 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.20 - 2023-10-12(19:02:08 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.19 - 2023-10-09(11:12:16 +0000)

### Fixes

- amxb_describe() returning non expected results over the pcb bus
- High CPU and Memory usage

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.18 - 2023-09-29(05:35:37 +0000)

### Fixes

- [tr181-device] Crash during boot and shutdown

## Release v3.6.17 - 2023-09-25(11:17:55 +0000)

### Fixes

- [tr181-device] Crash during boot

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.16 - 2023-09-21(13:09:29 +0000)

### Fixes

- amx path queries to pcb bus are missing entries
- Fix license headers in files

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.15 - 2023-09-14(20:46:59 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.14 - 2023-09-08(19:17:45 +0000)

### Fixes

- [tr181-device] Crash during boot

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.13 - 2023-09-01(08:01:44 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.12 - 2023-08-18(13:01:59 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.11 - 2023-07-28(11:28:03 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.10 - 2023-07-25(09:20:06 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.9 - 2023-07-19(13:56:05 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.8 - 2023-07-11(12:56:04 +0000)

### Fixes

- [USP] GSDM should return whether commands are (a)sync

## Release v3.6.7 - 2023-07-11(09:11:54 +0000)

### Changes

- [USP] GSDM should return whether commands are (a)sync

## Release v3.6.6 - 2023-07-05(14:28:44 +0000)

### Changes

- [AMX] Define default sockets in backends

## Release v3.6.5 - 2023-07-04(11:49:13 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.4 - 2023-06-27(18:58:58 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.3 - 2023-06-20(13:46:40 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.2 - 2023-06-15(06:46:42 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.1 - 2023-06-02(07:29:41 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.0 - 2023-05-31(12:30:52 +0000)

### New

- [AMX] Ambiorix should return the same error codes regardless of the used bus

## Release v3.5.6 - 2023-05-24(18:53:21 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.5.5 - 2023-05-10(14:45:26 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.5.4 - 2023-05-03(08:57:33 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.5.3 - 2023-04-22(14:20:48 +0000)

### Fixes

- has must fail on empty object lookup

## Release v3.5.2 - 2023-04-22(10:32:51 +0000)

### Fixes

- Fix unit tests, remove deprecated odl syntax

## Release v3.5.1 - 2023-04-22(09:31:23 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.5.0 - 2023-04-21(07:14:37 +0000)

### New

-  Implement capabilities and has function for object discovery

## Release v3.4.6 - 2023-04-20(11:10:09 +0000)

### Fixes

- [V12][USP] Push notification is not sent

## Release v3.4.5 - 2023-04-19(06:44:34 +0000)

### Fixes

- [V12][USP] Push notification is not sent

## Release v3.4.4 - 2023-04-17(09:59:15 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.4.3 - 2023-04-08(19:53:12 +0000)

### Fixes

- [USP][AMX] GSDM needs a ValueChangeType

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.4.2 - 2023-04-03(11:55:18 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- [amx pcb]Not possible to retrieve list of parameters and functions of a template object
- [USP] Download() is handled synchronously

## Release v3.4.1 - 2023-03-30(20:12:42 +0000)

### Fixes

- Onboarding Issue : Sometimes, PUBLISH is not sent

## Release v3.4.0 - 2023-03-28(09:32:27 +0000)

### New

- [AMX] Take bus access into account for GSDM

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.3.0 - 2023-03-27(10:35:31 +0000)

### New

- [pcb] usp endpoint doesn't support pcb requests

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.29 - 2023-03-18(06:54:55 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.28 - 2023-03-13(11:09:41 +0000)

### Fixes

- [Amxs][PCB] Amxs initial sync does not work with native pcb plugins

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.27 - 2023-02-28(12:24:40 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.26 - 2023-02-23(19:32:39 +0000)

### Fixes

- [USP] Get requests with search paths on pcb can fail

## Release v3.2.25 - 2023-02-22(18:17:36 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.24 - 2023-02-16(12:38:37 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.23 - 2023-02-13(17:39:39 +0000)

## Release v3.2.22 - 2023-02-13(17:26:24 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.21 - 2023-01-31(13:41:44 +0000)

### Fixes

- [USP][CDROUTER] GetSupportedDM on Device.LocalAgent. using a single object, first_level_only true, all options presents no event
- [USP] Get requests starting with Device and containing a search path are failing on sop

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.20 - 2023-01-18(10:40:48 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.19 - 2023-01-13(12:54:10 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.18 - 2023-01-12(07:37:52 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.17 - 2022-12-14(12:13:24 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.16 - 2022-12-07(10:05:30 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.15 - 2022-11-28(13:48:22 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.14 - 2022-11-21(15:04:09 +0000)

### Fixes

- [AMX] Missing functions in GSDM response

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.13 - 2022-11-19(17:40:44 +0000)

### Fixes

- [AMX] Missing functions in GSDM response

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.12 - 2022-11-15(16:27:07 +0000)

### Fixes

- Segmentation fault when stopping process

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.11 - 2022-11-14(09:57:48 +0000)

### Fixes

- Improve wait for and subscribe functionality

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.10 - 2022-11-03(16:18:37 +0000)

### Fixes

- [AMX] JSON string cannot be sent as event data

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.9 - 2022-10-24(12:53:40 +0000)

### Fixes

- Issue: Fix failing unit tests for set multiple

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.8 - 2022-10-20(16:35:35 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.7 - 2022-10-13(11:34:49 +0000)

### Fixes

- [USP][CDROUTER] GetSupportedDM on Device.LocalAgent. using a single object, first_level_only true, all options presents no event

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.6 - 2022-10-07(12:48:41 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- [USP][CDROUTER] GetSupportedDMResp presents wrong syntaxe of inner nested multi-instanceobject

## Release v3.2.5 - 2022-09-27(15:33:03 +0000)

### Fixes

- Get request with invalid path should fail

## Release v3.2.4 - 2022-09-27(12:12:08 +0000)

### Fixes

- [ACLManager]Crash when accessing pcb with user anonymous

## Release v3.2.3 - 2022-09-22(06:51:33 +0000)

### Changes

- [USP] Add requests with search paths will be allowed

## Release v3.2.2 - 2022-09-22(06:33:27 +0000)

### Fixes

- Key parameters must be added to add instance reply
- GSDM should return read-only attribute for key parameters

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.1 - 2022-09-12(15:44:03 +0000)

### Fixes

- [USP][CDROUTER] USP Agent never sent a notification to the controller
- [USP][CDROUTER] The agent sends the GetSupportedDMResp with missing "Device" when requested single object "Device.localAgent."

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.0 - 2022-09-12(08:24:11 +0000)

### Changes

- Support Ambiorix access restriction from PCB bus, NET-3484 [PCB][AMX][ACL] It must be possible to apply ACLS on amx components in a PCB environment

## Release v3.1.17 - 2022-08-29(10:35:14 +0000)

### Fixes

- [AMX] Allow back-ends to modify their config section

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.16 - 2022-08-24(12:01:20 +0000)

### Fixes

- [USP] TransferComplete! event does not have a Device. prefix

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.15 - 2022-08-18(16:47:01 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.14 - 2022-08-17(13:14:01 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.13 - 2022-08-05(10:59:14 +0000)

### Other

- Update dependencies in .gitlab-ci.yml

## Release v3.1.12 - 2022-07-26(15:43:08 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.11 - 2022-07-14(05:52:00 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- USP needs async userflags for functions

## Release v3.1.10 - 2022-07-11(08:57:18 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.9 - 2022-07-06(15:26:48 +0000)

### Fixes

- [USP] Unable to invoke FirmwareImage Download() command

## Release v3.1.8 - 2022-07-05(10:30:29 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.7 - 2022-06-30(08:48:41 +0000)

### Other

- Sort objects before building GSDM response

## Release v3.1.6 - 2022-06-28(12:32:39 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.5 - 2022-06-21(14:02:01 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.4 - 2022-06-09(16:58:12 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.3 - 2022-06-01(14:15:36 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.2 - 2022-05-23(15:15:17 +0000)

### Fixes

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when memory leaks are detected

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.1 - 2022-05-12(13:00:47 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- Add missing dependency to libpcb

## Release v3.1.0 - 2022-05-05(16:22:00 +0000)

### New

- Implement pcb backend function for get instances operator on PCB data models

### Fixes

- When subscribing on root object of mapped pcb datamodel no events are received

### Changes

- Update get supported data model implementation according to USP specification 1.2
- Update dependencies in .gitlab-ci.yml

## Release v3.0.10 - 2022-04-25(11:44:21 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.9 - 2022-04-06(13:41:07 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.8 - 2022-03-17(19:32:30 +0000)

### Fixes

- Segmentation fault when amxb_pcb_list is called with invalid path

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.7 - 2022-02-16(15:12:08 +0000)

## Release v3.0.6 - 2022-02-16(14:13:33 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.5 - 2022-02-07(07:24:38 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.4 - 2022-02-03(19:59:34 +0000)

### Fixes

- When using amxb_set_multiple without required parameters the return value is incorrect

## Release v3.0.3 - 2022-01-25(12:45:53 +0000)

### Fixes

- Make it possible to do partial sets on native PCB data models

## Release v3.0.2 - 2021-12-17(09:19:16 +0000)

### Changes

- Make it possible to do partial sets on native PCB data models

## Release v3.0.1 - 2021-12-16(10:59:48 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.0 - 2021-12-15(15:36:32 +0000)

### Breaking

- Update set interface according to changes in libamxb

## Release v2.2.9 - 2021-12-08(15:36:12 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.8 - 2021-12-02(11:49:53 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.7 - 2021-11-30(12:04:19 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.6 - 2021-11-23(13:43:22 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.5 - 2021-11-16(19:09:13 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.4 - 2021-11-10(20:50:39 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.3 - 2021-10-29(05:48:59 +0000)

### Fixes

- Fixes events from PCB mapper data models

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.2 - 2021-10-21(07:19:05 +0000)

### Changes

- Always return index path

## Release v2.2.1 - 2021-10-20(20:11:21 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.2.0 - 2021-10-13(13:11:49 +0000)

### New

- Update pcb back-end due to changes in libamxb

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.7 - 2021-09-24(18:29:43 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.6 - 2021-09-23(14:11:05 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.5 - 2021-09-13(20:37:07 +0000)

### Fixes

- Support request paths containing '/' separators in pcb backend

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.4 - 2021-08-23(11:55:49 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.3 - 2021-08-02(13:44:36 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.2 - 2021-07-22(12:45:20 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.1 - 2021-07-12(18:05:28 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.1.0 - 2021-07-12(09:18:40 +0000)

### New

- Add wait_for back-end implementation

## Release v2.0.25 - 2021-07-09(12:06:58 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.24 - 2021-07-05(07:37:25 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.23 - 2021-07-04(18:03:49 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.22 - 2021-07-02(19:44:57 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.21 - 2021-07-01(16:57:11 +0000)

### Fix

- Segmentation faults seen on target

## Release v2.0.20 - 2021-06-29(07:44:56 +0000)

### Changes

- Adapt pcb back-end to have support for deferred RPC methods

## Release v2.0.19 - 2021-06-21(14:36:33 +0000)

### Changes

- Use function amxb_request_get_ctx to get the bus context of a pending request
- Update dependencies in .gitlab-ci.yml

## Release v2.0.18 - 2021-06-19(06:30:45 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.17 - 2021-06-15(09:54:21 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.16 - 2021-06-14(09:52:47 +0000)

## Release v2.0.15 - 2021-06-11(11:37:51 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.14 - 2021-06-11(06:28:06 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.13 - 2021-06-10(20:28:37 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.12 - 2021-06-10(15:13:28 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.11 - 2021-06-08(18:15:41 +0000)

### Fixes

- Segmentation fault when data model returns a htable instead of a list for list operator
- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.10 - 2021-06-01(09:24:04 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.9 - 2021-05-31(12:07:21 +0000)

### Changes

- Operator lists takes template info flag into account
- Update dependencies in .gitlab-ci.yml

### Other

- Disable cross-compilation

## Release v2.0.8 - 2021-05-25(11:28:57 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.7 - 2021-05-21(13:25:58 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.6 - 2021-05-09(21:21:03 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.5 - 2021-05-04(12:56:34 +0000)

### Fixes

- uint16 function argument handled as int64

### Changes

- Use common macros from libamxc
- Update dependencies in .gitlab-ci.yml

### Other

- Enable auto opensourcing

## Release v2.0.4 - 2021-04-25(17:28:17 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.3 - 2021-04-21(10:01:54 +0000)

### Fixes

- When root objects are added or removed an event must be send to pcb_sysbus

### Changes

- Update dependencies in .gitlab-ci.yml

## Release 2.0.2 - 2021-04-15(20:26:38 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 2.0.1 - 2021-04-15(11:17:20 +0000)

### Fixes

- VERSION_PREFIX is needed in buildfiles 

## Release 2.0.0 - 2021-04-08(21:26:03 +0000)

### New

- Build-in data model RPC methods can conflict with domain specific RPCs

### Changes

- Move copybara to baf

## Release 1.0.9 - 2021-03-26(23:57:31 +0000)

### Fixes

- When a client subscribes for events future events must be taken into account
- [yocto] non -dev/-dbg/nativesdk- package contains symlink .so

## Release 1.0.8 - 2021-03-11(06:26:35 +0000)

### Changes

- Step-up versions of libamxc, libamxb, libamxp and libamxd for CI

## Release 1.0.7 - 2021-02-26(17:33:19 +0000)

### Changes

- Migrate to new licenses format (baf)
- Update back-end interface function table

## Release 1.0.6 - 2021-02-14(10:07:57 +0000)

### Changes

- Step-up versions of libs for CI

## Release 1.0.5 - 2021-01-31(21:14:53 +0000)

### Changes

- Step-up versions of libamxb and libamxd for CI/CD pipelines

## Release 1.0.4 - 2021-01-28(09:28:46 +0000)

### Changes

- Updates versions of libamxc,libamxp,libamxd,libamxb for CI/CD pipelines

### Fixes

- Adds reply end message on get root object

## Release 1.0.3 - 2021-01-18(18:04:48 +0000)

### New

- Generate make files using build agnostic file (baf)

### Changes

- Return empty array when no instances are deleted
- Verify root object is amx and fixes tests

### Fixes

- pcb function argument types are not correctly translated

## Release 1.0.2 - 2021-01-09(20:04:12 +0000)

### New

- Add tests for list operator.

### Fixes

- apply fixes for issues found with tests
- Remove code in comments

## Release 1.0.1 - 2021-01-08(20:25:12 +0000)

### Fixes

- Ci/CD Run tests in CI pipeline

## Release 1.0.0 - 2021-01-08(17:32:20 +0000)

### Changes

- Rewrite of all tests
- Apply new bus agnostic interfaces implementation
- Needs at least libamxb v2.0.0

### New

- Asynchronous list implementation

### Fixes

- PCB native resolve function


## Release 0.6.2 - 2020-11-30(17:17:39 +0000)

### Changes

- Update make file

## Release 0.6.1 - 2020-11-29(17:35:02 +0000)

### Changes

- Updates dependencies in gitlab CI yml file

## Release 0.6.0- 2020-11-26(09:13:47 +0000)

### Changes

- Redesign PCB object resolving
- Add tests
- Update readme

### Fixes

- Index or key path detection
- Fix debian package dependencies

## Release 0.5.4 - 2020-11-16(13:52:52 +0000)

### Changes

- Update gitlab CI/CD yml file

## Release 0.5.3 - 2020-11-02(06:27:14 +0000)

### Fixes

- When describing instances the path should not contain the index

## Release 0.5.2 - 2020-10-28(08:24:25 +0000)

### New

- Implement describe functionality

## Release 0.5.1 - 2020-10-19(19:48:06 +0000)

### Fixes

- When subscribing using pcb client on named paths with depth 0 no events are received
- Invoking a function on an index path fails

## Release 0.5.0 - 2020-10-02(16:03:21 +0000)

### Changes

- Update code style
- amxb_pcb_get should be able to return object tree recursive

## Release 0.4.6 - 2020-09-23(12:22:45 +0000)

### Fixes

- Fixes subscriptions, use index path instead of named path
- Subscriptions are always in index path notation

## Release 0.4.5 - 2020-09-17(14:03:28 +0000)

### Fixes 

- PCB back-end must accept configuration options

### New 

- Add support for get_supported_dm on native PCB data models

## Release 0.4.4 - 2020-09-13(20:31:48 +0000)

### Fixes 

- amxb_get segfaults when using amxb_pcb as backend

## Release 0.4.3 - 2020-09-03(20:02:29 +0000)

### Changes

- Removes useless dependency (libamxb)

## Release 0.4.2 - 2020-09-03(16:28:47 +0000)

### Fixes

- Fixes g++ warnings & errors

### Changes

- added VERSION_PREFIX to support legacy build system

## Release 0.4.0 - 2020-08-30(08:44:20 +0000)

### Changes

- Applies libamxd API changes
- Common macros moved to libamxc
- Needs libamxd version 1.0.0 or higher

### Fixes

- Subscriptions taken from a native pcb client with a specific depth never receives any events

## Release 0.3.0 - 2020-08-22(15:54:28 +0000)

### New

- Implements PCB basic get operator
- Supports search paths on native PCB data models

## Release 0.2.12 - 2020-08-20(13:38:34 +0000)

### Fixes

- set correct MAJOR number on libraries for internal builds
- Fixes shadowed variable, issue #4
- Fixes PCB compatible events/notifications
- Fixes clang warning, unused assignment

### Changes

- Drop PCB notifications if object was deleted (can not be fetched) 
- Report test results

### New

- Translates PCB notifications to amxd events
- Ignore PCB events when both ends support ambiorix

## Release 0.2.11 - 2020-08-13(13:47:50 +0000)

### New

- Send Ambiorix data model events as custom PCB events, to make event filtering not bus dependent

### Fixes

- PCB compatible events - take request attributes into account

## Release 0.2.10 - 2020-08-10(08:43:40 +0000)

### Fixes

- Fixes event object paths

## Release 0.2.9 - 2020-08-04(06:46:21 +0000)

### Fixes

- Set template_only when function can not be used on instance

### Changes

- Improves error translation
- Depth with templates/instances
- Update contributing guide

## Release 0.2.8 - 2020-07-27(12:00:00 +0000)

### Fixes

- Bus specific back-end must use describe action for parameter introspection

## Release 0.2.7 - 2020-07-24(13:52:54 +0000)

### Changes

- Reduces the use of regular expressions
- Adds RAW_VERSION to makefile.inc, VERSION must be X.Y.Z or X.Y.Z-HASH

### Fixes

- Compilation issue with frotified musl

## Release 0.2.6 - 2020-07-13(06:35:05 +0000)

### Fixes

- Uses new string_split API of libamxc
- Fixes changed events

## Release 0.2.5 - 2020-07-06(08:10:05 +0000)

- Applies API updates (amxp slots, amxb_subscribe)

## Release 0.2.4 - 2020-07-05(17:50:14 +0000)

### Changes

- Use std=c11 instead of std=c18, to support older compilers and toolchains
- Use logical expression instead of regexp (new API)

## Release 0.2.3 - 2020-06-30(08:26:24 +0000)

### Changes

- Scrub Component.* files

### Fixes

- Only return child objects of templates when request_getobject_template_info is set (issue #3)

## Release 0.2.2 - 2020-06-26(18:19:08 +0000)

### New

- Copybara file

### Changes

- csv_string and ssv_string are string variants in pcb

## Release 0.2.1 - 2020-06-24(08:47:35 +0000)

### Fixes 

- Creates symbolic link to backend so without version
- Timestamp variant must be converted to and from pcb datetime variant type

## Release 0.2.0 - 2020-06-19(14:27:07 +0000)

### New

- `datetime` type for parameters, function return and function arguments

## Release 0.1.5 - 2020-06-16(12:57:04 +0000)

### New

- Sends parameter changed events

### Changes

- update license to BSD+patent

## Release 0.1.4 - 2020-05-06(14:45:54 +0000)

### New

- add instance handler and del instance handler

## Release 0.1.3 - 2020-05-04(07:09:41 +0000)

### New

- Request handlers for set and get parameters

### Fixes

- Some too long functions

## Release 0.1.2 - 2020-04-03(17:05:08 +0000)

### Changes

- Makes notifications more uniform and pcb compatible

## Release 0.1.1 - 2020-03-31(09:14:20 +0000)

### New

- Data model registration
- PCB compatible get object request handler implementation
- PCB compatible introspect, skip private objects and functions
- Support for publishing notifications and receiving subscriptions
- Fixes tests, function callback return type
- Support for method calls, including argument verification

## Release 0.1.0 - 2020-02-25(21:20:36 +0000)

### Changes

- Support for libamxb v0.1.0, not backwards compatible

## Release 0.0.3 - 2020-02-24(21:37:53 +0000)

### New 

- Initial tests
- Package creation

### Changes

- Use default pipeline via yml templates

## Release 0.0.2 - 2020-02-20(12:50:53 +0000)

### Fixes

- Failed connection scenario error handling and cleanup
- Makefile - removes /usr/local/include path from CFLAGS
- Makefile - removes sahtrace lib from LDFLAGS
- Split source file into multiple files

### New 

- AMXB subscribe implementation for PCB notifications

## Release 0.0.1 - 2020-01-21(10:02:42 +0100)

- Initial release
