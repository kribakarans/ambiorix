# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## Release v1.3.9 - 2024-04-11(14:37:56 +0000)

### Changes

- Make amxb timeouts configurable

## Release v1.3.8 - 2024-02-26(11:07:49 +0000)

### Other

- [prpl] Authorization header uses 'bearer' instead of 'Bearer'

## Release v1.3.7 - 2023-11-29(22:01:37 +0000)

### Changes

- [ServiceID][WebUI] set correct acl settings for webui

## Release v1.3.6 - 2023-11-06(09:33:44 +0000)

### Changes

- - [UI][LAN versus WAN admin] Allow the WAN and the LAN UI to have different ACL(users)

## Release v1.3.5 - 2023-10-30(16:47:20 +0000)

### Changes

- [ConnDB][WebUI] Create a webui for the connection database

## Release v1.3.4 - 2023-10-25(08:39:33 +0000)

### Fixes

- [amx-fcgi]Segfault detected with unit-tests

## Release v1.3.3 - 2023-10-09(10:54:34 +0000)

## Release v1.3.2 - 2023-09-25(11:50:51 +0000)

### Fixes

- - [prpl][amx-fcgi] amx_fcgi_http_subscribe return wrong status code

## Release v1.3.1 - 2023-09-14(20:29:31 +0000)

### Fixes

- - [amx-fcgi] admin user cannot add to Device.Routing.Router.[Alias=='main'].IPv4Forwarding.

## Release v1.3.0 - 2023-09-14(13:51:15 +0000)

### New

- [amx-fcgi] Add reporting of number of unsuccessful login attempts

## Release v1.2.5 - 2023-08-22(06:38:19 +0000)

### Other

- [amx-fcgi][SWUpdate] Upload command should stream file directly to the disk

## Release v1.2.4 - 2023-08-22(06:10:54 +0000)

### Fixes

- - [prpl][user-management] Users role paths are not tr181 paths

## Release v1.2.3 - 2023-07-05(11:24:41 +0000)

### Fixes

- [amx-fcgi] Error 404 on REST API call on a empty table result

## Release v1.2.2 - 2023-06-28(17:11:07 +0000)

### Changes

- Add requests with search paths are allowed

## Release v1.2.1 - 2023-06-01(20:59:42 +0000)

### Fixes

- [TR181-DeviceInfo][FCGI] Add rpc to read/write a file

## Release v1.2.0 - 2023-05-26(18:18:08 +0000)

### New

- [TR181-DeviceInfo][FCGI] Add rpc to read/write a file

## Release v1.1.0 - 2023-05-24(18:35:23 +0000)

### New

- [amx-fcgi]Refactor sessions code to make it easier to run the provided web-ui example

## Release v1.0.1 - 2023-05-12(13:36:07 +0000)

### Other

- - [HTTPManager][Login] Increase unit test coverage

## Release v1.0.0 - 2023-05-11(09:44:44 +0000)

### Other

- - [HTTPManager][Login][amx-fcgi] Create a session

## Release v0.5.4 - 2023-05-10(14:25:25 +0000)

### Other

- Issue: ambiorix/applications/amx-fcgi#16 Document how to launch the example webui in a container

## Release v0.5.3 - 2023-03-31(11:19:27 +0000)

## Release v0.5.2 - 2023-03-31(06:23:33 +0000)

### Fixes

- Fix and complete unit tests

## Release v0.5.1 - 2023-03-17(09:48:11 +0000)

## Release v0.5.0 - 2023-03-15(14:08:49 +0000)

### New

- [amx-fcgi][SWUpdate] Add upload file functionality

## Release v0.4.9 - 2023-02-16(12:06:26 +0000)

### Other

- Remove unneeded dependencies
- [amx-fcgi] generated datamodel documentation is empty

## Release v0.4.8 - 2023-02-13(17:09:44 +0000)

## Release v0.4.7 - 2023-02-09(06:55:08 +0000)

### Fixes

- amx-fastcgi crashes at boot when webui is installed in LCM container

## Release v0.4.6 - 2023-02-02(10:51:11 +0000)

### Fixes

- amx-fastcgi crashes at boot when webui is installed in LCM container

## Release v0.4.5 - 2022-11-28(13:02:39 +0000)

### Fixes

- Fix wrong usage of function amxd_path_setf

## Release v0.4.4 - 2022-11-14(10:08:07 +0000)

## Release v0.4.3 - 2022-10-13(06:26:20 +0000)

### Other

- Improve plugin boot order

## Release v0.4.2 - 2022-10-07(12:32:04 +0000)

### Other

- Remove configuration for lighttpd

## Release v0.4.1 - 2022-09-22(06:13:32 +0000)

### Changes

- Re-add demo/example web-ui

## Release v0.4.0 - 2022-09-13(10:54:58 +0000)

### Fixes

- Issue: HOP-1897- [UI] UI broken on WNC config

## Release v0.3.5 - 2022-08-18(18:48:08 +0000)

### Fixes

- Issue: Unit tests for send-events are failing

## Release v0.3.4 - 2022-07-27(09:43:38 +0000)

## Release v0.3.3 - 2022-06-01(13:57:36 +0000)

### Other

- Use amxa_get to avoid code duplications

## Release v0.3.2 - 2022-05-23(14:58:57 +0000)

### Fixes

- [Gitlab CI][Unit tests][valgrind] Pipeline doesn't stop when memory leaks are detected

## Release v0.3.1 - 2022-05-17(08:50:13 +0000)

### Other

- Rework configuration to work with default lighttpd

## Release v0.3.0 - 2022-05-12(12:38:05 +0000)

### New

- Add implementation for seBatch

## Release v0.2.3 - 2021-12-02(11:31:43 +0000)

### Fixes

- Fixes segfault in test

## Release v0.2.2 - 2021-11-30(14:49:01 +0000)

### Other

- Opensource component

## Release v0.2.1 - 2021-11-30(11:43:25 +0000)

### Changes

- Code clean-up for search path subscriptions

## Release v0.2.0 - 2021-11-25(13:26:22 +0000)

### New

- Add asynchronous command

## Release v0.1.2 - 2021-11-23(13:21:23 +0000)

### Changes

- Complete the README.md file

## Release v0.1.1 - 2021-11-10(20:34:40 +0000)

### Changes

- Add unit-tests for event streams and subscriptions

### Other

- Issue: ambiorix/applications/amx-fcgi#11 Add unit tests for sending events

## Release v0.1.0 - 2021-10-29(07:03:10 +0000)

### New

- Add ACL verification

### Changes

- Add startup order
- It must be possible to invoke native commands
- Unit tests must verify the returned status code in the responses

## Release v0.0.1 - 2021-10-21(07:15:02 +0000)

### Changes

- Unit tests must be added
- Add event filtering
- Update body requests-responses to plain objects

### Other

- Issue: ambiorix/applications/amx-fcgi#4 Start-up script must be added

