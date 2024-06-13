# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v6.5.1 - 2024-05-07(09:57:02 +0000)

### Other

- [amxd] amxd_trans_set_param with NULL value makes the amxd_trans_apply failIgnore null variants

## Release v6.5.0 - 2024-03-19(17:00:32 +0000)

## Release v6.4.2 - 2024-03-14(21:51:56 +0000)

### Other

- Datamodel application generic performance improvement

## Release v6.4.1 - 2024-02-06(11:44:03 +0000)

### Other

- Crash pwhm on lb6

## Release v6.4.0 - 2024-01-26(06:21:06 +0000)

### Other

- [Ambiorix] Amxb_set and amxb_del should return more info about each parameter

## Release v6.3.0 - 2024-01-18(12:49:30 +0000)

### Changes

- [ambiorix][synchronization]The synchronization library must also synchronize sub-objects when an instance is added

## Release v6.2.1 - 2024-01-10(10:44:10 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.2.0 - 2024-01-08(14:09:08 +0000)

### Other

- call destroy callback on root object destruction

## Release v6.1.4 - 2023-12-12(20:20:48 +0000)

## Release v6.1.3 - 2023-12-12(20:15:36 +0000)

## Release v6.1.2 - 2023-12-12(09:31:45 +0000)

### Fixes

- [AMX] Make it possible to _exec functions with braces

## Release v6.1.1 - 2023-12-06(12:33:51 +0000)

### Changes

- Add and update documentation

## Release v6.1.0 - 2023-11-29(18:28:01 +0000)

### New

- Add posibility for action handlers to provide a description

### Fixes

- tr181-usermanagement segfault during startup
- Update and extend documentation

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.15 - 2023-11-21(14:51:41 +0000)

### Fixes

- [AMX] Only return objects that contain the parameter

## Release v6.0.14 - 2023-11-21(11:32:36 +0000)

### Fixes

- [AMX] Only return objects that contain the parameter

## Release v6.0.13 - 2023-11-17(12:25:44 +0000)

## Release v6.0.12 - 2023-11-04(20:36:35 +0000)

### Changes

- [CDROUTER][USP] usp_conformance_10_13 : Cannot add a new MQTT BulkData Profile
- Update dependencies in .gitlab-ci.yml

## Release v6.0.11 - 2023-10-17(13:28:38 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.10 - 2023-10-12(11:45:18 +0000)

### Fixes

- [PRPL OJO NOKIA][GMAP] The GMap server crashes when a new wired device, like an IP printer or IP camera, is plugged in.

## Release v6.0.9 - 2023-10-09(06:28:39 +0000)

### Fixes

- amxb_describe() returning non expected results over the pcb bus

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.8 - 2023-09-25(05:59:18 +0000)

### Fixes

- [PRPL][SAFRAN] Wan is not up after reset, only after additional reboot

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.7 - 2023-09-21(11:07:47 +0000)

### Fixes

- Subscriptions on mib objects not correctly removed
- Fix license headers in files

## Release v6.0.6 - 2023-09-14(18:27:05 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.5 - 2023-09-08(10:14:12 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.4 - 2023-09-01(06:17:50 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.3 - 2023-08-18(11:09:47 +0000)

### Fixes

- Add documentation about data model modules - extensions

## Release v6.0.2 - 2023-07-25(06:55:16 +0000)

### Fixes

- It is not possible to declare events in a mib

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.1 - 2023-07-19(12:01:22 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v6.0.0 - 2023-07-10(13:18:00 +0000)

### Breaking

- [USP] GSDM should return whether commands are (a)sync

## Release v5.1.4 - 2023-06-27(17:21:17 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v5.1.3 - 2023-06-20(08:38:13 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v5.1.2 - 2023-06-14(20:43:32 +0000)

### Fixes

- Failing transactions not fully cleaned

### Other

- Issue: ambiorix/libraries/libamxd#153 Sending an object event with object, eobject or path in the event data causes never ending loop

## Release v5.1.1 - 2023-05-31(12:04:11 +0000)

### Fixes

- [AMX] Ambiorix should return the same error codes regardless of the used bus

## Release v5.1.0 - 2023-05-25(15:39:23 +0000)

### New

- [USP] Add specific error codes for get instances

## Release v5.0.4 - 2023-05-24(14:30:53 +0000)

### Fixes

- Add documentation to default action implementations

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v5.0.3 - 2023-05-10(09:19:21 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v5.0.2 - 2023-05-09(17:36:01 +0000)

### Fixes

- Fix regression in amxd_path api

## Release v5.0.1 - 2023-05-08(07:25:07 +0000)

### Fixes

- [unit-tests] Complete and extend unit tests

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v5.0.0 - 2023-05-03(06:26:39 +0000)

### Breaking

- gsdm missing arguments for commands and events

### Fixes

- [AMX] Changing optional parameters gives no events

## Release v4.4.4 - 2023-04-24(11:15:16 +0000)

### Fixes

- access to DM LocalAgent. using amxb_get fail on EW

## Release v4.4.3 - 2023-04-21(16:57:22 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.4.2 - 2023-04-08(17:56:32 +0000)

### Fixes

- [USP][AMX] GSDM needs a ValueChangeType

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.4.1 - 2023-03-28(07:31:28 +0000)

### Fixes

- [uspagent] The 'Discovery' object in the dm cannot use gsdm

## Release v4.4.0 - 2023-03-28(06:00:41 +0000)

### New

- [AMX] Take bus access into account for GSDM

## Release v4.3.0 - 2023-03-27(05:55:28 +0000)

### New

- [pcb] usp endpoint doesn't support pcb requests

## Release v4.2.7 - 2023-03-17(13:39:46 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.2.6 - 2023-03-13(07:42:36 +0000)

### Fixes

- Mop test netmodel_02_check_interfaces_test.py::test_wan_isup_query_loop fails due to unexpected out argument

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.2.5 - 2023-03-02(08:58:18 +0000)

### Fixes

- [AMX] Protected objects should not be retrieved by gsdm

## Release v4.2.4 - 2023-02-28(08:58:16 +0000)

### Fixes

- [amxd] methods with amxd_aattr_out argument return NULL

## Release v4.2.3 - 2023-02-22(14:42:29 +0000)

### Fixes

- Ignore empty read filter
- amxd_object_get_param_value should have its object parameter const

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.2.2 - 2023-02-16(10:26:24 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.2.1 - 2023-02-13(12:32:48 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.2.0 - 2023-02-13(10:55:21 +0000)

### New

- [USP] Requirements for Get further clarified

### Fixes

- Data model functions arguments don't inherit attributes from mib

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.1.7 - 2023-01-30(17:23:29 +0000)

### Changes

- [USP] Requirements for Get changed
- Update dependencies in .gitlab-ci.yml

## Release v4.1.6 - 2023-01-13(11:50:39 +0000)

### Fixes

- [ambiorix] [regression] transaction time is dependent on the number of parameters within the object

## Release v4.1.5 - 2023-01-11(20:46:46 +0000)

### Fixes

- [AMX][USP] A get on a protected parameter with public bus access must fail
- [ambiorix] transaction time is dependent on the number of parameters within the object

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.1.4 - 2022-12-14(09:32:48 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.1.3 - 2022-12-07(08:09:04 +0000)

### Fixes

- Add instance response is wrong when using key path notation on ubus

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.1.2 - 2022-11-25(14:28:16 +0000)

### Fixes

- Issue #147 Add and update documentation for amxd_path API

### Other

- Fix some typos in the documentation

## Release v4.1.1 - 2022-11-21(13:15:56 +0000)

### Fixes

- [AMX] Missing functions in GSDM response

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.1.0 - 2022-11-19(12:22:55 +0000)

### New

- Add function to retrieve parameter path

### Fixes

- [AMX] Missing functions in GSDM response

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- Add new error code amxd_status_not_supported
- Issue: ambiorix/libraries/libamxd#148 Add new error code amxd_status_not_supported

## Release v4.0.5 - 2022-11-15(12:41:01 +0000)

### Fixes

- [AMX] Get with search path returns too many results

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.0.4 - 2022-11-14(07:51:13 +0000)

### Fixes

- Do not use expression to filter parameters on name or attributes
- Investigate and fix klocwork reports for ambiorix libs and tools

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- [AMX] Improve documentation of amxd_object function with regard to events
- [AMX] Improve documentation of amxd_object function with regard to events

## Release v4.0.3 - 2022-11-03(11:45:54 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.0.2 - 2022-10-24(10:58:28 +0000)

### Fixes

- Parameter attributes are not correctly checked when adding the parameter to an object

## Release v4.0.1 - 2022-10-20(14:44:52 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v4.0.0 - 2022-10-12(12:29:50 +0000)

### Fixes

- Issue: Fix _describe RPC method definition

### Other

- [USP][CDROUTER] GetSupportedDM on Device.LocalAgent. using a single object, first_level_only true, all options presents no event

## Release v3.6.22 - 2022-10-06(19:02:42 +0000)

### Fixes

- [USP][CDROUTER] GetSupportedDMResp presents wrong syntax of inner nested multi-instanceobject

## Release v3.6.21 - 2022-10-05(18:54:38 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.20 - 2022-10-05(12:56:51 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.19 - 2022-09-20(14:59:18 +0000)

### Fixes

- GSDM should return read-only attribute for key parameters

### Changes

- [USP] Add requests with search paths will be allowed

## Release v3.6.18 - 2022-09-12(13:04:41 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.17 - 2022-08-29(07:53:39 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.16 - 2022-08-24(09:28:28 +0000)

### Fixes

- [amx] custom param read handler called more often than expected

## Release v3.6.15 - 2022-08-18(13:17:24 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.14 - 2022-08-17(09:01:19 +0000)

### Fixes

- allow_partial is not set as an input argument for the set operation

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.13 - 2022-08-05(09:09:52 +0000)

### Fixes

- [amx] certain NumberOfEntries fields not updated

## Release v3.6.12 - 2022-07-25(09:03:59 +0000)

## Release v3.6.11 - 2022-07-25(06:55:01 +0000)

### Fixes

- Set amxd_object_free as public API method

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.10 - 2022-07-13(12:01:10 +0000)

### Other

- Issue: ambiorix/libraries/libamxd#141 Default object write action fails when only setting optional parameters

## Release v3.6.9 - 2022-06-28(10:24:46 +0000)

### Fixes

- Supported commands under multi-instance objects are not returned

### Changes

- Make it possible to read hidden values depending on the access level

## Release v3.6.8 - 2022-06-21(06:25:18 +0000)

### Changes

- Add support for mutable keys

## Release v3.6.7 - 2022-06-09(11:35:36 +0000)

### Fixes

- The default rpc _get must be able to support parameter paths

## Release v3.6.6 - 2022-06-01(12:24:15 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.5 - 2022-05-30(08:45:50 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.4 - 2022-05-23(11:25:45 +0000)

### Fixes

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when memory leaks are detected

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.6.3 - 2022-05-19(15:27:35 +0000)

### Changes

- Add reference following for reference lists using indexes
- Update dependencies in .gitlab-ci.yml

## Release v3.6.2 - 2022-05-12(10:23:06 +0000)

### Changes

- Update path parser to be able to detect reference path

## Release v3.6.1 - 2022-05-05(11:31:51 +0000)

### Changes

- Update get supported data model implementation according to USP specification 1.2
- [MQTT] Topic must be writable after creation

## Release v3.6.0 - 2022-04-25(08:35:23 +0000)

### New

- Add internal data model RPC _get_instances

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.5.3 - 2022-04-06(10:28:08 +0000)

### Fixes

- Remove macro IS_SET
- It is not possible to add multiple times the same object action callback with different private data

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.5.2 - 2022-03-17(10:54:37 +0000)

### Fixes

- Aliases containing dots causes problems when used in object paths

## Release v3.5.1 - 2022-03-09(08:16:52 +0000)

### Fixes

- Use dyncast to get the index out of a variant

## Release v3.5.0 - 2022-02-15(05:58:25 +0000)

### New

- Add API to get applied mib names

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.4.0 - 2022-02-14(12:03:21 +0000)

### New

- Add permission denied status code

### Other

- Issue: ambiorix/libraries/libamxd#125 Update documentation on return variant of transaction

## Release v3.3.2 - 2022-02-04(15:41:23 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.3.1 - 2022-01-25(06:40:29 +0000)

### Fixes

- Allow object write with only optional parameters
- Adding a valid MIB to an object with a transaction makes the transaction fail
- Objects added using a mib can not be addressed with search path or named path
- Correct allow partial for set

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.3.0 - 2021-12-14(12:10:51 +0000)

### New

- Add support for allow partial in set operator

## Release v3.2.15 - 2021-12-08(13:03:03 +0000)

### Changes

- When a parameter is of csv or ssv type all individual values must be verified with check_enum or check_is_in
- Make it possible to set relative parameter references in validators

## Release v3.2.14 - 2021-11-29(14:54:35 +0000)

### Fixes

- Documentation mentions wrong type for object iterations macros

## Release v3.2.13 - 2021-11-22(15:39:32 +0000)

### Fixes

- Improve default set action

## Release v3.2.12 - 2021-11-16(17:38:52 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.11 - 2021-11-10(12:55:33 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.10 - 2021-10-28(22:22:08 +0000)

### Fixes

- Infinite loop when removing parent object having underlying depth greater than 10
- Amxd_object_remove_mib removes mibs when they are not added

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.9 - 2021-10-20(18:56:49 +0000)

### Fixes

- Amxd_path_get_type returns a bool

### Changes

- Always return index path
- Update dependencies in .gitlab-ci.yml

## Release v3.2.8 - 2021-10-08(13:05:50 +0000)

## Release v3.2.7 - 2021-10-08(10:35:15 +0000)

## Release v3.2.6 - 2021-10-08(07:29:51 +0000)

### Changes

- `_get` function must return multi-instance objects when access is protected
- Update dependencies in .gitlab-ci.yml

## Release v3.2.5 - 2021-09-24(15:35:45 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.4 - 2021-09-23(09:48:25 +0000)

### Fixes

- Key parameters must be validated when instance is created
- Instances with Alias parameter containing a dot can not be deleted
- method amxd_object_for_all can be invoked on any object

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.2.3 - 2021-09-07(05:22:10 +0000)

### Fixes

- GCC11 archlinux compiler warning

## Release v3.2.2 - 2021-08-23(10:41:16 +0000)

### Fixes

- Cannot remove last part from path if it ends with an asterisk
- Verifying if an object has a parameter can cause a segmentation fault

### Changes

- Update dependencies in .gitlab-ci.yml

### Other

- Issue: ambiorix/libraries/libamxd#102 Add macro to iterate over the content of objects that can be nested

## Release v3.2.1 - 2021-08-02(12:10:15 +0000)

### Changes

- Make amxd_function_are_args_valid function public
- Destroy action callbacks must be called bottom-up

## Release v3.2.0 - 2021-07-22(11:15:15 +0000)

### New

- Add function to append amxd_path_t

### Fixes

- Applying a transaction without an object selected causes a segmentation fault

## Release v3.1.6 - 2021-07-12(17:16:15 +0000)

### Fixes

- When removing part of a path, the type must be recalculated

## Release v3.1.5 - 2021-07-09(09:20:16 +0000)

### Fixes

- Add unit test that shows bug

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.4 - 2021-07-09(08:35:38 +0000)

### Fixes

- When providing a instance path to get supported it must fail

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.3 - 2021-07-05(06:44:39 +0000)

### Changes

- Makes it possible to store private data in function definitions

## Release v3.1.2 - 2021-07-04(17:13:49 +0000)

### Changes

- Makes it possible to enable or disable custom parameter and object actions without removal and re-adding

## Release v3.1.1 - 2021-07-02(18:49:24 +0000)

### Fixes

- When amxd_trans_apply fails on enum string parameter it calls validation function from a different parameter
- Length validation on csv or ssv string parameters is always failing

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.1.0 - 2021-06-28(12:46:02 +0000)

### New

- Make it possible for RPC methods to defer the result

### Fixes

- The data model  is sending to many events

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.6 - 2021-06-21(07:40:09 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.5 - 2021-06-18(22:38:02 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v3.0.4 - 2021-06-15(08:31:34 +0000)

### Fixes

- When multiple add-inst action callbacks are added to an multi-instance object multiple instances are created
- Destroy function will be called forever if it does not get an amxd_status_ok

## Release v3.0.3 - 2021-06-11(09:20:02 +0000)

### Fixes

- Fixes checking of parameter names
- Fixes checking of valid parameter names

## Release v3.0.2 - 2021-06-11(05:28:24 +0000)

### Fixes

- Fixes del operator, due to change in behavior of amxd_object_resolve_... functions

## Release v3.0.1 - 2021-06-10(18:07:17 +0000)

## Release v3.0.0 - 2021-06-10(11:59:44 +0000)

### Breaking

- Search paths should only be expanded if there is a match

### Fixes

- GetSupportedDM does not return enough information when the first_level_only flag is set

## Release v2.0.11 - 2021-06-08(08:56:03 +0000)

### Fixes

- [tr181 plugins][makefile] Dangerous clean target for all tr181 components

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.10 - 2021-06-01(06:51:38 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.9 - 2021-05-31(09:12:16 +0000)

### Fixes

- Negative object indexes and names can occur

### Changes

- It must be possible to disable template information
- Update dependencies in .gitlab-ci.yml

## Release v2.0.8 - 2021-05-21(11:51:34 +0000)

### Fixes

- amxd_object_get_path with flag AMXD_OBJECT_SUPPORTED returns wrong path on instances

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.7 - 2021-05-09(20:23:59 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.6 - 2021-05-04(07:50:07 +0000)

### Changes

- Use common macros from libamxc
- Update dependencies in .gitlab-ci.yml

### Other

- Enable auto opensourcing

## Release v2.0.5 - 2021-04-23(18:38:52 +0000)

### Changes

- Update dependencies in .gitlab-ci.yml

## Release v2.0.4 - 2021-04-21(08:44:02 +0000)

### Changes

- It must be possible to add user flags to functions

## Release v2.0.3 - 2021-04-19(13:20:28 +0000)

### Fixes

- enum_check fails if parameter has attribute %key

## Release 2.0.2 - 2021-04-18(15:00:54 +0000)

### Fixes

- Parameters with attribute %key are not immutable 

## Release 2.0.1 - 2021-04-15(20:02:15 +0000)

### Changes

-  remove fakeroot dependency on host to build WRT image 

## Release 2.0.0 - 2021-04-08(20:24:26 +0000)

### Fixes

- Fixes build supported path
- Correct copybara scrubbing order
- Memory leaks in read test and to many reads when object action read is invoked
- Adds test case for supported path builder
- Improve check if objects exists using describe RPC

### New

- Build-in data model RPC methods can conflict with domain specific RPCs

### Changes

- Move copybara to baf

## Release 1.3.1 - 2021-03-29(17:19:39 +0000)

### New

- Transactions must be able to add mib to object

## Release 1.3.0 - 2021-03-24(11:05:48 +0000)

### Changes

- Step-up version of libamxc for CI/CD
- It must be possible to add tags or flags to parameters

## Release 1.2.9 - 2021-03-10(11:46:22 +0000)

### Changes

- Step-up versions of libamxc and libamxp for CI
- It must be possible to limit number of instances with a parameter reference
- It must be possible to filter parameters on attributes

## Release 1.2.8 - 2021-02-25(13:46:10 +0000)

### Changes

- Migrate to new licenses format (baf)
- Add doxygen documentation to functions
- Large inline functions should be moved to implementation files

### Fixes

- There seems to be an inconsistency between parameters setters and getters for objects.
## Release 1.2.7 - 2021-02-14(08:09:31 +0000)

### Changes

- Step-up versions of libamxc and libamxp for CI

## Release 1.2.6 - 2021-01-31(15:51:47 +0000)

### Fixes 

- When selecting a NULL object in a transaction, the transaction apply crashes

## Release 1.2.5 - 2021-01-28(08:56:23 +0000)

### Changes

- Updates versions of libamxc and libamxp for CI/CD pipelines

## Release 1.2.4 - 2021-01-18(14:54:10 +0000)

### New

- Auto generate make files using build agnostic files

### Changes

- Return empty array when no instances are deleted and no error code
- Instance add/delete events must clearly provide the key parameters

### Fixes

- Only include objects in static library
- Sets correct type of parameter values in set function

## Release 1.2.3 - 2021-01-04(14:52:08 +0000)

### Changes

- Improve introspection (describe)

### Fixes

- Send object add events when MIBs are added

## Release 1.2.2 - 2020-11-30(15:41:32 +0000)

### Changes

- Update makefiles

### Fixes 

- When defining arguments the in attribute must now be set explicitly

## Release 1.2.1 - 2020-11-30(10:07:11 +0000)

### Fixes

- Hotfix: parameter attributes are not correctly set

## Release 1.2.0 - 2020-11-29(16:49:20 +0000)

### Changes

- Update dependencies in gitlib CI yml file

## Release 1.1.8 - 2020-11-25(19:02:31 +0000)

### Changes

- The get supported datamodel arguments should be more in line with USP

### Fixes

- Invalid object retrieval using partial name

## Release 1.1.7 - 2020-11-25(09:02:52 +0000)

### Changes

- Modify implementation of default data model get function
- Get operator on multi-instance objects with depth 0 fails

## Release 1.1.6 - 2020-11-23(11:13:01 +0000)

### Changes

- Make the default data model RPC functions more USP compliant
- Update readme
- List and describe functions take rel_path into account
- Get supported handles rel_path argument
- Delete returns array of all deleted objects
- Creates correct response for add instance
- Parameters values for set and add can be a relative parameter path
- Adds 'rel_path' argument to all default data model functions
- Update readme

## Release 1.1.5 - 2020-11-16(12:42:26 +0000)

### Changes

- Updates gitlab CI/CD yml file

### Fixes

- Virtual root object does not contain any functions

## Release 1.1.4 - 2020-11-01(21:39:46 +0000)

### Fixes

- Remove name and index from instance paths in describe return struct

## Release 1.1.3 - 2020-10-27(17:48:17 +0000)

### Changes

- Add access arguments to describe and list functions
- Extend describe functionality

### Fixes

- Status codes to string conversion not complete
- Automatic instance counters are not correctly added to instances

## Release 1.1.2 - 2020-10-19(19:04:22 +0000)

### New

- Add 8 and 16 bit integer support to transactions

### Fixes 

- Instances are added when invalid values are provided

## Release 1.1.1 - 2020-10-14(07:10:06 +0000)

### New

- Add support for 8 and 16 bit integers parameters in data model
- Add protected attribute for parameters, functions and parameters

### Fixes

- Corrected spelling mistake in docs of amxd_object_findf

### Changes

- Added API documentation

## Release 1.1.0 - 2020-10-02(13:38:23 +0000)

### Changes

- Update code style
- Add api function amxd_dm_get_object
- Add ^ symbol in path for go up in hierarchy

### New

- It must be possible to get a sub-tree recursive

### Fixes 

- Mibs are not correctly added to instance objects

## Release 1.0.7 - 2020-09-23(10:34:42 +0000)

### New

- Add function to get first part of path

## Release 1.0.6 - 2020-09-21(21:04:19 +0000)

### Changes

- Fetch object path with or without terminating dot

## Release 1.0.5 - 2020-09-17(20:37:33 +0000)

### Fixes

- Do not send add or delete events for template objects in template objects

## Release 1.0.4 - 2020-09-13(20:07:16 +0000)

### Fixes

- When an empty search path is provided the object itself matches when resolving
- Parameters in the data model must have a fixed type.

## Release 1.0.3 - 2020-09-05(19:27:04 +0000)

### New

- Adds `amxd_object_for_all` to iterate over all instances matching a search path

## Release 1.0.2 - 2020-09-03(14:01:14 +0000)

### Fixes

- Pass version_prefix to make command

## Release 1.0.1 - 2020-09-03(06:01:14 +0000)

### Fixes

- Fixes g++ compilation warnings and errors

### Changes

- Add version prefix to support legacy build system
- Adds invalid action in actions enum

### New

- Tests for `get_supported` feature
- amxd_path_t struct and API and tests for amxd_path_t

## Release 1.0.0 - 2020-08-29(20:52:47 +0000)

### New

- Support for get_supported_dm USP requests
- Introduces access levels - public, protected, private
- New APIs amxd_path_split_path_param, amxd_path_from_supported_path, amxd_function_get_attrs, amxd_action_can_add_function, amxd_action_can_add_param

### Changes

- Breaking API changes in amxd_object_list, amxd_object_describe, amxd_object_list_functions,  amxd_object_describe_functions, amxd_object_get_function_count, amxd_object_get_params, amxd_object_list_params, amxd_object_describe_params, amxd_object_get_param_count

### Fixes

- Automatic instance counters are not always correctly added to the data model and do not update
- Resolved object paths must end with a dot
- Fixes typos in documentation
- Fixes memory leak 
- Fixes typo in function name

## Release 0.6.6 - 2020-08-23(15:38:45 +0000)

### New

- New parameter validation and parameter read action implementations

### Fixes

- Fixes rollback of objects with read-only parameters
- Fixes derived object actions search for instance objects

## Release 0.6.5 - 2020-08-21(17:20:57 +0000)

### Changes 

- Makes it possible to remove fixed path parts from list

## Release 0.6.4 - 2020-08-20(12:58:19 +0000)

### Fixes 

- set correct MAJOR number on libraries for internal builds

## Release 0.6.3 - 2020-08-16(09:50:13 +0000)

### Fixes 

- An object write action without arguments or parameter values must fail

### New

- Extra `alias` parameter tests

## Release 0.6.2 - 2020-08-13(11:33:22 +0000)

### Changes

- Prepend object paths with a dot, make object paths inline with TR-369 specifications

### New

- Adds object path functions
- Add path function to extract fixed path part

## Release 0.6.1 - 2020-08-10(08:32:21 +0000)

### Fixes

- Fixes event paths (dot terminated)

## Release 0.6.0 - 2020-08-04(05:22:51 +0000)

### Changes

- Updates default RPC method get - adds `rel_path` argument
- `get` RPC method support for `Search Paths`
- Update contributing guide
- Breaking API changes to better support Alias and unique keys - `amxd_object_new_instance` and `amxd_object_add_instance`

### New

- Support for searching with expressions and wildcards
- Maximum instance set and check using object_action_add_inst
- Support for addressing by unique key
- Support for `Alias` parameter

## Release 0.5.11 - 2020-07-27(21:26:56 +0000)

### Fixes

- Describe parameter action must fetch value through read action

## Release 0.5.10 - 2020-07-27(11:34:18 +0000)

### Changes

- Only continue in base implementation search when not implemented is returned

## Release 0.5.9 - 2020-07-24(11:28:08 +0000)

### Fixes

- Validate action must not change the value
- Fixes destroy action recursion in tree

### Changes

- Reduces the use of regular expressions
- Adds arguments to default describe function definition

### New

- Added amxd_object_set_csv_string_t and amxd_object_set_ssv_string_t.
- Added action callback management functions

## Release 0.5.8 - 2020-07-22(18:38:13 +0000)

### Changes

- Adds RAW_VERSION to makefile.inc, VERSION must be X.Y.Z or X.Y.Z-HASH

### Changes

- Adds extra status codes

## Release 0.5.6 - 2020-07-19(19:38:55 +0000)

### Fixes

- Removes invalid return value
- Instances must inherit attributes from template

## Release 0.5.5 - 2020-07-17(19:51:41 +0000)

### New 

- Adds amxd_object_find_instance function, finds an instance using (key) expression

### Changes

- Makes function amxd_object_expr_get_field public

### Fixes

- Fix compilation with fortified  musl
- Fixes typos in changelog

## Release 0.5.4 - 2020-07-16(05:59:13 +0000)

### New

- Key parameter support (USP TR-369)
- `amxd_object_add_instance` API, fully validates key parameters

## Release 0.5.3 - 2020-07-14(12:44:12 +0000)

### Fixes

- Added missing consts in `amxd_parameter_set_value` and `amxd_param_validate` functions

## Release 0.5.2 - 2020-07-13(05:28:37 +0000)

### Changes

- Update makefiles for SAH legacy build systems
- Uses new string split API of libamxc
- Periodic inform events on data model objects
- Update README.md

### Fixes

- Sends change event when auto instance counter has been changed

### New

- Documentation (WIP) actions,transactions and events

## Release 0.5.1 - 2020-07-06(07:37:25 +0000)

### Changes

- Add and delete events contain parameters and their values (expression filtering)

## Release 0.5.0 - 2020-07-05(15:21:32 +0000)

### Changes 

- Uses new api for slot filtering (libamxp)
- Parameter validation functions must be adapted due to amxc_var_compare issue
- All (node) names must be according to tr-106 specifications

## Release 0.4.5 - 2020-06-30(07:45:20 +0000)

### Changes

- Scrubs Component.* files

## Release 0.4.4 - 2020-06-29(16:22:07 +0000)

### New

- Support for legacy SAH build system

## Release 0.4.3 - 2020-06-26(17:14:56 +0000)

### Changes

- Data model events can be triggered (immediate execution of callbacks)
- Install libraries into target specific output directory

### New

- Copybara file
- Document about usp support (tr369 + tr106)

## Release 0.4.2 - 2020-06-22(10:43:31 +0000)

### Changes

- Provide base objects (base_singleton & base_template)
- Derive all objects from base objects

## Release 0.4.1 - 2020-06-20(18:50:37 +0000)

### Fixes

- Attributes can not be set on mib objects
- Check for function duplicates
- Segfault when fetching root of mib-object
- object_add_mib & object_remove_mib returns not_found when mib was not found

### Changes

- Split function amxd_dm_action_invoke

## Release 0.4.0 - 2020-06-19(14:12:17 +0000)

### New

- Date time type (timestamps) support for parameters, function return, function arguments
- Support for data model MIBs (object extensions)

### Changes

- Move private object functions in separate c-file.

## Release 0.3.3 - 2020-06-16(11:02:31 +0000)

### Changes

- Make it possible to use MAC addresses as object name or key, changed name validation

## Release 0.3.2 - 2020-06-15(18:05:36 +0000)

### Fixes

- Automatic instance counters are not correctly initialized after start up
- It must be possible to add multiple cb functions for each action

### New

- Adds object changed event
- Adds signals app:start & app:stop to data model, instance counters connect to app:start

### Changed

- update license to BSD+patent
- Improves describe and list actions and adds tests
- Uses attribute max, easier maintenance when adding attributes

## Release 0.3.1 - 2020-06-09(07:07:19 +0000)

### New

- Default parameter value validation actions and tests

## Release 0.3.0 - 2020-06-04(12:42:38 +0000)

### New

- Adds parameter action tests
- Adds automatic instance counter testing
- Adds describe action (objects & parameters) and describe function for methods
- Adds default describe method
- Adds default parameter actions
- Creates unit tests results text file (for ELK)

## Release 0.2.8 - 2020-05-27(08:37:52 +0000)

### Fixes

- Fixes typo in define: AMXD_OJBECT_REGEXP vs AMXD_OBJECT_REGEXP

## Release 0.2.7 - 2020-05-27(08:07:15 +0000)

### New

- Automatic instance counter parameter (function amxd_object_set_counter)
- Relative path (function amxd_object_get_rel_path)
- Extra flag for path generation (AMXD_OJBECT_REGEXP), escapes all special regexp chars in path

## Release 0.2.6 - 2020-05-19(09:29:10 +0000)

### Fixes

- Fixes copy of template parameters to instances, 

### New

- Adds function to change data model method implementation

## Release 0.2.5 - 2020-05-18(07:37:21 +0000)

### Fixes

- Fixes delete notifications

## Release 0.2.4 - 2020-05-18(05:54:13 +0000)

### New

- Adds parameter_get_type function to retrieve parameter type
- Adds function_get_type function to retrieve function return type
- Adds function to get error string from status

### Fixes

- Fixes memory leak

## Release 0.2.3 - 2020-05-14(14:37:09 +0000)

### Fixes

- Fixes delete event when changing parameter values

## Release 0.2.2 - 2020-05-13(08:19:48 +0000)

### New

- Transactions
  - Select object, set, add instance and delete instance
  - Validates changed objects
  - Auto revert when one action fails

### Fixes

- Removes add and del functions from read-only template objects
- Private instances can only be deleted when private flag is set
- Adds action object tree definition
- Fixes recursive actions

### Changes

- Emitting of signals is done in transactions, removed from object functions
- Emits signals bottom to top when deleting objects
- Default functions using transactions
- Defines default actions

## Release 0.2.1 - 2020-05-07(11:32:43 +0000)

### New 

- Protects against recursive actions

## Release 0.2.0 - 2020-05-06(13:26:18 +0000)

### New

- object actions: 'instance add', 'instance delete', 'object destroy'
- default data model functions 'add' and 'delete' for template objects

### Changes

- re-organization of header files
- renamed some functions

## Release 0.1.0 - 2020-05-01(13:21:17 +0000)

### New

- Data model parameters
- Object actions "action_object_list", "action_object_read", "action_object_write"
- Added tests: parameters, actions

## Release 0.0.9 - 2020-04-01(18:02:36 +0000)

### New

- Adds object signal emit

### Fixes

- Finding instance objects

## Release 0.0.8 - 2020-03-31(08:53:03 +0000)

### Fixes

- Emits correct signal when removing instance object

## Release 0.0.7 - 2020-03-23(10:34:04 +0000)

### New

- Doxygen documentation for part of the API
- Amxp signal emit when adding and deleting objects
- Status codes and modified functions to return correct status codes
- More unit tests

### Fixes

- Fixes issues detected by unit tests

## Release 0.0.6 - 2020-03-18(20:59:05 +0000)

### Changed

- Adds more checks and verifications when invoking functions

## Release 0.0.5 - 2020-03-18(11:52:16 +0000)

### Changed

- Provide depth in walk callback functions

## Release 0.0.4 - 2020-03-16(20:40:08 +0000)

### New

- Data model functions 

## Release 0.0.3 - 2020-03-10(10:30:29 +0000)

### New

- More tests object and object hierarchy
- Walk the data model function (with filtering)

## Release 0.0.2 - 2020-03-09(07:20:59 +0000)

### Add

- Tests for object hierarchy

### New

- Debian package creation

## Release 0.0.1 - 2020-03-06(17:00:00 +0000)

- Initial version - Data Model Object Hierarchy
