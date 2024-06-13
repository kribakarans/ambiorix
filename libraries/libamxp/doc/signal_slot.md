# Signal / Slot

## __Table of Contents__  

[[_TOC_]]

## Introduction

The signal/slot implements a simple observer pattern. 

From [wikipedia](https://en.wikipedia.org/wiki/Observer_pattern)

> The **observer pattern** is a software design pattern in which an object, called the **subject**, maintains a list of its dependents, called **observers**, and notifies them automatically of any state changes, usually by calling one of their methods.

In this implementation the **subject** is called a `signal` and the **observers** are called `slots`

The Ambiorix `signal/slot` mechanism can help in solving one-to-many dependencies between `objects` (functionality)  without making the `objects` (functions) tightly coupled.

To make the signal/slot mechanism work, an event-loop is needed. The event-loop must monitor the Ambiorix `signal` file descriptor

## Event Loops

The `signal/slot` feature is designed to be used in event-driven applications and there for it is very high importance to have an event loop. Ambiorix itself does not provide an implementation of an event loop as there are may good, well tested implementations available. Some examples of libraries that can be used to create an event-loop are:

- [libevent](https://libevent.org/)
- [libuv](http://docs.libuv.org/en/v1.x/)

In this document all examples of the event loop code are using `libevent`.

### Add signal-slot support to your event-loop

To make the `signal/slots` work the event loop must monitor the Ambiorix `signal` file descriptor for read. The file descriptor can be fetched using:

```C
int amxp_signal_fd(void);
```

The returned file descriptor can only be read.

Whenever data is available for read the event loop implementation should call

```C
int amxp_signal_read(void);
```

This function will return `zero` when a `signal` has been read and handled. It will return a `none-zero` value when no `signal` was available or an error occurred.

**libevent code example**

In this example the error handling is left-out of the code, in real life (production) error handling must be added.

```C
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#define UNUSED __attribute__((unused))

static struct event_base *base = NULL;
static struct event *amxp_sig = NULL;

static void el_amxp_signal_read_cb(UNUSED evutil_socket_t fd,
                                   UNUSED short flags,
                                   UNUSED void *arg) {
    amxp_signal_read();
}

static void el_create(void) {
    base = event_base_new();

    amxp_sig = event_new(base,
                         amxp_signal_fd(),
                         EV_READ | EV_PERSIST,
                         el_amxp_signal_read_cb,
                         NULL);
    event_add(amxp_sig, NULL);
}

static void el_destroy(void) {
    event_base_free(base);
    free(amxp_sig);
}

int main(int argc, char *argv[]) {
    el_create()

    event_base_dispatch(base);

    el_destroy();
    return 0;
}
```

## Signals

Signals are grouped in an `object` - the signal manager - and can be emitted or triggered by any part of the application that has access to the signal manager that contains the signal.

Multiple signal managers can exist at any time and there is always the global signal manager available. Each signal manager can contain an open-ended number of `signals`.

Signals are defined by a name an that name must be unique within the signal manager the signal is defined in.

Any open-ended number of slots can be connected to any signal, or slots can be connected to all signals of one or all signal managers. 

### Creating a signal manager

It is good practice to create a signal manager for your `domain` and populate that signal manager with `pre-defined` signals that are well documented.

A signal manager can be created in different ways:

1. On the stack (as a static variable)
2. On the heap (memory allocation)

The `Ambiorix` libamxp provides API functions for both cases.

```C
int amxp_sigmngr_init(amxp_signal_mngr_t *sig_mngr);
int amxp_sigmngr_new(amxp_signal_mngr_t **sig_mngr);
```

When the signal manager is not needed anymore, it should be `cleaned-up` using one of the functions:

```C
int amxp_sigmngr_clean(amxp_signal_mngr_t *sig_mngr);
int amxp_sigmngr_delete(amxp_signal_mngr_t **sig_mngr);
```

These clean-up (destructor) functions are matching the initialize (constructor) functions. So if you created a signal manager on the stack and initialized it with `amxp_sigmngr_init` you will need `amxp_sigmngr_clean` to clean it up when you do not need it anymore.

If you allocated a signal manager on the heap using `amxp_sigmngr_new` you will need to call `amxp_sigmngr_delete` to clean it up and free the allocated memory when you do not need the signal manager any more.

***Code Example***

```C
#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>

static amxp_signal_mngr_t MySigMngr;

int main(int argc, char *argv[]) {
    amxp_sigmngr_init(&MySigMngr);

    // Do some stuff here (like create an event-loop)

    amxp_sigmngr_clean(&MySigMngr);

    return 0;
}
```

#### Make Your Signal Manager Available

If you created or instantiated your own signal manager it is no use to others if they can not access it, as they need to be able to connect slots to the signals of your signal manager.

This problem can be solved in several ways:

1. Add a function that returns the signal manager pointer. The disadvantage of this approach is that your signal manager becomes fully public, others can add signals to it as well.

2. Add functions that allow others to connect slots to your signal manager. The disadvantage of this approach is that you need to "duplicate" some of the slot functions in Ambiorix amxp library.

#### Use the global signal manager

The Ambiorix amxp library provides a `global` signal manager. This one can be used by any one and is accessible using the amxp library signal/slot APIs. All functions in the amxp library taking a signal manager pointer as argument will use the `global` signal manager when that pointer is set to NULL.

### Defining and Adding Signals

Signals are basically a name, just consider it as the name of the `event`.

The easiest way to add signals to a signal manager (or event the `global` signal manager) is by using 

```C
int amxp_sigmngr_add_signal(amxp_signal_mngr_t * const sig_mngr,
                            const char *name)
```

This will add a new signal to the provide signal manager, or the `global` signal manager when the `sig_mngr` pointer is set to NULL.

Keep in mind that the name of the signal must be unique within a signal manager. The function will return `zero` when the signal was added and a `none-zero` value when it failed to add the signal. A duplicate signal name will make the function fail.

A signal can be removed as well by using:

```C
int amxp_sigmngr_remove_signal(amxp_signal_mngr_t * const sig_mngr,
                               const char *name);
```
This will remove the signal with the given name (if such a signal exists) from the provided signal manager (or the `global` signal manager if the pointer given is NULL). When removing a signal it can not be emitted or triggered again, and all connected slots are disconnected.

### Emit or Trigger Signals

There are two ways that the slots (which are basically call back functions) can be invoked:

1. Immediately (trigger) 
2. From the main event loop (emit)

Triggering signals will work without the need of an event-loop, but could lead to un-intended recursion. As the main goal of the signal/slot implementation is to be able to let others now of occurred `events` or `state changes` the emitting signals is preferred before triggering signals.

When using the emit method, an event-loop must be available and monitoring the amxp `signal` file descriptor. If no event-loop is available or the event-loop is not monitoring the amxp `signal` file descriptor the slots will not be called.

The amxp API functions to trigger or emit a signal are:
```C
void amxp_sigmngr_trigger_signal(const amxp_signal_mngr_t * const sig_mngr,
                                 const char *name,
                                 const amxc_var_t * const data);
int amxp_sigmngr_emit_signal(const amxp_signal_mngr_t * const sig_mngr,
                             const char *name,
                             const amxc_var_t * const data);
```

When the provided `sig_mngr` pointer is NULL, the `global` signal manager is used.

It is possible to pass data to the slots using the `data` argument which is an amxc variant, which can be a primitive variant or a composite variant.

## Slots

Slots are callback functions. When a signal is emitted or triggered, all connected slots (callback functions) will be called.

### Connecting Slots

The function signature of a slot is fixed and must match:

```C
typedef void (*amxp_slot_fn_t) (const char * const sig_name,
                                const amxc_var_t * const data,
                                void * const priv);
```

A slot can be connected to one single signal or to many signals at once (or even to all).

To connect a slot to a single slot use:

```C
int amxp_slot_connect(amxp_signal_mngr_t * const sig_mngr,
                      const char * const sig_name,
                      const char * const expression,
                      amxp_slot_fn_t fn,
                      void * const priv);
```

When the signal manager pointer is set to NULL the `global` signal manager is used. A logical expression can be provided, to filter on the signal data.
The slot will only be called when the expression evaluates to true or when no data is provided with the signal. The expression is optional, when none provided the slot is always called whenever the signal is emitted or triggered.

Optionally some `private` data can be added to the connect as well. This private data will be passed `as is` to the slot when the signal is emitted or triggered.

When a slot is connected to a specific signal (using the above function), calling it again using the same slot (function pointer) has no effect.

Connect a slot to all (or some) signals at once is also possible, even to signals that do not exist yet.

```C
int amxp_slot_connect_all(const char * const sig_reg_exp,
                          const char * const expression,
                          amxp_slot_fn_t fn,
                          void * const priv);
```

Here the first argument is a (optional) regular expression. When not provided (NULL), the slot is connected to all existing signals of all existing signal managers. If after the connect new signal managers are created or new signals are added, the slot will be automatically connected to them as well.

When the first argument is provided (which is a regular expression), the slot is connected to all existing signals of all existing signal managers where the signal name matches the regular expression. If after the connect new signals or signal managers are created, the slot will be connected to the signal if it matches the regular expression.

Connect a slot to multiple signals of a specific signal manager is also possible:

```C
int amxp_slot_connect_filtered(amxp_signal_mngr_t * const sig_mngr,
                               const char * const sig_reg_exp,
                               const char * const expression,
                               amxp_slot_fn_t fn,
                               void * const priv);
```

This function works exactly the same as the `amxp_slot_connect_all` except that it will only take the signals of the provided signal manager into account.
When no signal manager is provided (NULL)

### Disconnecting Slots

Slots can be disconnected as well using one of these functions:

```C
int amxp_slot_disconnect(amxp_signal_mngr_t * const sig_mngr,
                         const char * const sig_name,
                         amxp_slot_fn_t fn);

int amxp_slot_disconnect_with_priv(amxp_signal_mngr_t *sig_mngr,
                                   amxp_slot_fn_t fn,
                                   void *priv);

void amxp_slot_disconnect_all(amxp_slot_fn_t fn);
```

The first function will disconnect the slot (fn) from the signal with the given name `sig_name` in the provided signal manager (or the `global` when NULL).
If the slot was connected to signals using a regular expression, the slot will be disconnect if the name `sig_name` is matching the regular expression.

The second function will disconnect all connections of the slot (fn) for which the same private data (priv) was given.

The last will disconnect the slot (fn) from all signals.

## Limitations

- It is not possible to disconnect a slot in the slot implementation it self.
- Data passed MUST be an amxc variant. Other (C) structures or data pointers can be embedded in a `custom` amxc variant.