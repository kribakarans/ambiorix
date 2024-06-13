# Unit Test Utility Library

[[_TOC_]]

## Introduction

`Lib_amxut` is a library providing utilities for writing unittests for Ambiorix components.

The goal of this library is as follows:
- Avoid that each component copy-pasting the same test setup and helper functions
- Avoid part of the timewaster of setting up unittests in each component by having the
  common functionality in this library rather than making it work again in each component.

Currently supported:
- dummy bus (without sockets)
- reusable setup and teardown of ambiorix libraries (odl parser, datamodel, bus backend, bus
  connection, ...)

## Building, installing and testing

First, install 
[libamxc](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxc),
[libamxp](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxp),
[libamxb](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxb),
[libamxd](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxd),
[libamxo](https://gitlab.com/prpl-foundation/components/ambiorix/libraries/libamxo),
[libsahtrace](https://gitlab.com/soft.at.home/network/libsahtrace),
[amxb_dummy](https://gitlab.com/prpl-foundation/components/ambiorix/modules/amxb_backends/amxb_dummy)
as per instructions of their README.

Next, in the docker container created while installing the above libraries,
```bash
mkdir -p ~/amx_project/libraries/
cd ~/amx_project/libraries/
git clone git@gitlab.com:prpl-foundation/components/ambiorix/tools/libraries/libamxut.git
cd libamxut
export VERSION_PREFIX="master_"
make
sudo -E make install
```

### Testing

Tester helper libraries need to be tested too!

To run the test, run (in the docker container):
```bash
cd ~/amx_project/libraries/libamxut/tests
make
```

Or this command if you also want the coverage tests to run:

```bash
cd ~/amx_project/libraries/libamxut/tests
make run coverage
```

The coverage report placed in `output/x86_64-linux-gnu/coverage/report/`.

## Usage

To start using `libamxut` in your tests you need to:
- Add `-lamxut` to your `LDFLAGS` (Usually in `./test/test_defines.mk`)
- Add `libamxut` and `amxb-dummy` as a test dependencies (`TEST_DEPS`) of the pipeline (`.gitlab-ci.yml`)

Example:
```diff
diff --git a/.gitlab-ci.yml b/.gitlab-ci.yml
index 5f25c73..e94db1b 100644
--- a/.gitlab-ci.yml
+++ b/.gitlab-ci.yml
@@ -1,6 +1,6 @@
 variables:
   BUILD_DEPS: libamxc libamxp libamxd libamxo libamxb libamxm libnetmodel sah-lib-sahtrace-dev
-  TEST_DEPS:
+  TEST_DEPS: "libamxut amxb-dummy"
   BUILD_TARGET: tr181-httpaccess
   COMPONENT_EXTRA_TOOLS: "amxo-cg amxo-xml-to"
 
 include:
diff --git a/test/test_defines.mk b/test/test_defines.mk
index 6819163..52854a8 100644
--- a/test/test_defines.mk
+++ b/test/test_defines.mk
@@ -20,7 +20,7 @@ CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
 
 LDFLAGS += -fkeep-inline-functions -fkeep-static-functions \
                   $(shell pkg-config --libs cmocka) -lamxc -lamxp -lamxd -lamxo -lamxb -lamxm -ldl -lpthread \
-                  -lnetmodel -lsahtrace
+                  -lnetmodel -lsahtrace -lamxut
 
 WRAP_FUNC=-Wl,--wrap=
 

```