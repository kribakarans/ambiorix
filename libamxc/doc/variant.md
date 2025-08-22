# Variant Data Container

[[_TOC_]]

## Introduction

In `C` programming language all data types are always `fixed` types which can not change at run-time. This makes it hard to define functions or callbacks of which some of the arguments could be a different type depending on the situation. Typically in `C` programming this is solved by using `void *` and `casting. The disadvantage of this technique is that you lose type information, which could lead to unwanted side effects.

Many other programming language have a `variant` type, this is a structure that can hold any type of data, without losing the data type information.

From [wikipedia - Variant Type](https://en.wikipedia.org/wiki/Variant_type)

> Variant is a data type in certain programming languages, particularly Visual Basic, OCaml, Delphi and C++ when using the Component Object Model.

In `C` programming language the same functionality can be achieved by using a `tagged union`.

From [wikipedia - Tagged Union](https://en.wikipedia.org/wiki/Tagged_union)

> In computer science, a tagged union, also called a variant, variant record, choice type, discriminated union, disjoint union, sum type or coproduct, is a data structure used to hold a value that could take on several different, but fixed, types. Only one of the types can be in use at any one time, and a tag field explicitly indicates which one is in use. It can be thought of as a type that has several "cases", each of which should be handled correctly when that type is manipulated. This is critical in defining recursive datatypes, in which some component of a value may have the same type as the value itself, for example in defining a type for representing trees, where it is necessary to distinguish multi-node subtrees and leafs. Like ordinary unions, tagged unions can save storage by overlapping storage areas for each type, since only one is in use at a time.

The `Ambiorix variant data container` is a tagged union and can contain many different types, each variant can hold only one data type at a given point in time.

##  Supported Variant Types

The `Ambiorix variant` by default supports a set of data types, which can be separated into `primitive` and `composite` data types.

The default supported `primitive` data types are:

- null - `void` or `NULL`
- string - `char *`
- signed 8 bit integer - `int8_t`
- signed 16 bit integer - `int16_t`
- signed 32 bit integer - `int32_t`
- signed 64 bit integer - `int64_t`
- unsigned 8 bit integer - `uint8_t`
- unsigned 16 bit integer - `uint16_t`
- unsigned 32 bit integer - `uint32_t`
- unsigned 64 bit integer - `uint64_t`
- floating point - `float`
- double - `double`
- file descriptor `int` 
- timestamp - `amxc_ts_t`
- boolean - `bool`

A `composite` data type is one that contains many variants, like a linked list of variants or a table containing key-value pairs where each value is a variant.

The default supported `composite` data types are:

- list - `amxc_llist_t` - contains a linked list of variants
- htable - `amxc_htable_t` - contains a hash table of variants, each item in the hash table has a key and a value. The value is a variant.

> **NOTE ABOUT STRING TYPES**
> 
> Some special string types are supported as well: these are just strings, but as the variant type is different, it conains extra information. These types are:<br>
> - csv_string - contains a string of `Comma Separated Values`
> - ssv_string - contains a string of `Space Separated Values`

> **NOTE ABOUT FILE DESCRIPTOR TYPES**
>
> A file descriptor in the Linux system is represented as an integer. When setting a file descriptor as a variant type, the variant implementation is verifying that the given integer is a valid file descriptor.

> **NOTE ABOUT TIMESTAMP TYPES**
> 
> Timestamps are not a standard `C` type and are implemented in this library as a structure. The timestamp structure is considered a `primitive` as it does not contain multiple variants.

This set of `variant types` is the default set, it is possible to add your own `custom` types. How a custom type can be added is not handled in this document.

##  Using Variants

### Construct and Destruct a Variant

As with all `C` variables, you can define variants on the stack or allocate memory from the heap.

To define a local variant on the stack and initialize it:

```C
amxc_var_t MyVariant;
amxc_var_init(&MyVariant);
```

To allocate memory from the heap:

```C
amxc_var_t *pMyVariant = NULL;
amxc_var_new(&pMyVariant);
```

Both methods will create a variant containing a `null` type. It is also important to clean-up the variant when not needed anymore.

```C
amxc_var_clean(&MyVariant);
amxc_var_delete(&pMyVariant);
```

The function `amxc_var_clean` will free all internally allocated memory (if any) to store the data, and will `reset` the variant back to the `null` type. This function can be used as well on variants that are allocated on the heap. After calling `amxc_var_clean` the variant variable is still usable.

The function `amxc_var_delete` will also free the memory that was allocated with `amxc_var_new` and resets the pointer to NULL.

### Type Names and Type Identifiers

Each type has an identifier (integer) and a name (string). The default supported types have the following identifers and names:

- ID = `AMXC_VAR_ID_NULL`, name = `null`
- ID = `AMXC_VAR_ID_CSTRING`, name = `cstring_t`
- ID = `AMXC_VAR_ID_INT8`, name = `int8_t`
- ID = `AMXC_VAR_ID_INT16`, name = `int16_t`
- ID = `AMXC_VAR_ID_INT32`, name = `int32_t`
- ID = `AMXC_VAR_ID_INT64`, name = `int64_t`
- ID = `AMXC_VAR_ID_UINT8`, name = `uint8_t`
- ID = `AMXC_VAR_ID_UINT16`, name = `uint16_t`
- ID = `AMXC_VAR_ID_UINT32`, name = `uint32_t`
- ID = `AMXC_VAR_ID_UINT64`, name = `uint64_t`
- ID = `AMXC_VAR_ID_FLOAT`, name = `float`
- ID = `AMXC_VAR_ID_DOUBLE`, name = `double`
- ID = `AMXC_VAR_ID_BOOL`, name = `bool`
- ID = `AMXC_VAR_ID_LIST`, name = `amxc_llist_t`
- ID = `AMXC_VAR_ID_HTABLE`, name = `amxc_htable_t`
- ID = `AMXC_VAR_ID_FD`, name = `fd_t`
- ID = `AMXC_VAR_ID_TIMESTAMP`, name = `amxc_ts_t`
- ID = `AMXC_VAR_ID_CSV_STRING`, name = `csv_string_t`
- ID = `AMXC_VAR_ID_SSV_STRING`, name = `ssv_string_t`

Depending on the function or macro used, the identifier must be specified, or the name.

> **NOTE ABOUT CUSTOM TYPES**
>
> Custom variant types can be defined, when such a custom type is `registered` an identifier is assigned to it, the name is provided when registering the custom type. The chosen identifier can be different each time, there for you need to fetch the identifier using the custom type's name. A function is available for this `amxc_var_get_type_id_from_name`. How to define and register your own custom type is out of the scope of this document and will be explained in a separate doucment.

### Changing the Type

When a variant is instantiated, it is always a `null` variant. This type does not contain any data. Changing the type of a variant can be done using the function

```C
int amxc_var_set_type(amxc_var_t * const var, const uint32_t type);
```

The type identifier (argument `type`) can be any of the type identifiers as mentioned in [Type Names and Type Identifiers](#type-names-and-type-identifiers)

When changing or setting the type of the variant the current data stored in the variant is removed and the variant will contain the default value of the `type` set. The default value for integer, float, double is `0`, for booleans `false`, for timestamps `unknown time`, for strings `null string`, for list an empty linked list, for htable an empty hash table.

For primitive types it is not needed to first set the type and then set the value. The value can be set immediately after instantiating the variant.

### Checking the Type

Often it is needed to check that the type contained in a variant is the type that is expected. 

To get the type identifier of a variant use the function:

```C
uint32_t amxc_var_type_of(const amxc_var_t * const var);
```

This function will return the type identifier of the contained data.

To fetch the name of the type contained in the variant use:

```C
const char *amxc_var_type_name_of(const amxc_var_t * const var);
```

Note that this function is returning a `const char *`, there is no need to free the returned pointer (it is not possible as it is `const`).

### Setting Values

#### Setting Primitive Values

Setting `primitive` values is easy and can be done by using the `amxc_var_set` macro. This macro can be used directly after instantiating the variant.

```C
amxc_var_t my_var;

amxc_var_init(&my_var);
amxc_var_set(cstring_t, &my_var, "Hello World");
```

The macro takes as first argument the type name, as second the pointer to the variant, and as last argument the value. The value `type` must match the type mentioned as first argument.

The macro uses the type name and not the type identifier. The preprocessor will translate this macro into a function call.

```C
int amxc_var_set_cstring_t(amxc_var_t * const var, const char * const val);
```

#### Setting Composite Values

Building a composite variant - that is a variant containing variants - requires a little bit more effort, by executing following steps:

- Instantiate the variant
- Set the corect `composite` type
- Fill the variant

For the first two steps the functions `amxc_var_init` and `amxc_var_set_type` can be used, for the last step the macros `amxc_var_add` or `amxc_var_add_key` depending on the composite type used.

To build a variant containing a linked list of variants

```C
amxc_var_t my_var;

amxc_var_init(&my_var);
amxc_var_set_type(&my_var, AMXC_VAR_ID_LIST);
amxc_var_add(cstring_t, &my_var, "Hello");
amxc_var_add(cstring_t, &my_var, "World");
```

To build a variant containing a key - value pairs where the values are variants.
The keys are always strings.

```C
amxc_var_t my_var;

amxc_var_init(&my_var);
amxc_var_set_type(&my_var, AMXC_VAR_ID_HTABLE);
amxc_var_add_key(cstring_t, &my_var, "key1", "Hello");
amxc_var_add_key(cstring_t, &my_var, "key2", "World");
```

It is possible to create a variant containing a linked list of variants, where each variant in the linked list is a variant containing key-value pairs.

Example:

Let's assume you have a list of users and for each user a user-id, name, and access rights. In `C` a structure can be defined containing this data and a linked list iterator, to be able to add this data in a linked list.

```C
typedef struct _system_user {
    uint32_t user_id;
    char *name;
    uint32_t access_rights;
    amxc_llist_t lit;
} system_user_t;
```

A function to add an instance of this `user` information could look like this (without error checking):

```C
void add_user(amxc_llist_t *users, uint32_t user_id, const char *name, uint32_t access_rights) {
    int name_length = strlen(name);
    system_user_t *user = calloc(1, sizeof(system_user_t));
    user->user_id = user_id;
    user->name = calloc(1, name_length + 1);
    strcpy(user->name, name);
    user->access_rights = access_rights;

    amxc_llist_append(users, &user->lit);
}
```

Other functions can then call this one to add an instance, example:

```C
amxc_llist_t *my_worker_function(void) {
    amxc_llist_t *my_users = NULL;
    amxc_llist_new(&my_users);

    add_user(my_users, 1, "John Doe", 0x755);
    add_user(my_users, 2, "Jane Doe", 0x644);
    add_user(my_users, 3, "Super", 0x777);

    return my_users;
}
```

The same can be achieved with variants, but now you do not need to define a `fixed` structure, all you need is a variant that is initialized as a `list` type.

The function could look like (without error checking):

```C
void add_user(amxc_var_t *users, uint32_t user_id, const char *name, uint32_t access_rights) {
    amxc_var_t *user = amxc_var_add(amxc_htable_t, users, NULL);
    amxc_var_add_key(uint32_t, user, "user_id", user_id);
    amxc_var_add_key(cstring_t, user, "name", name);
    amxc_var_add_key(uint32_t, user, "access_rights", access_rights);
}
```

Others can then use this function to fill the variant list

```C
amxc_var_t *my_worker_function(void) {
    amxc_var_t *my_users = NULL;
    amxc_var_new(&my_users);
    amxc_var_set_type(my_users, AMXC_VAR_ID_LIST);

    add_user(my_users, 1, "John Doe", 0x755);
    add_user(my_users, 2, "Jane Doe", 0x644);
    add_user(my_users, 3, "Super", 0x777);

    return my_users;
}
```


The first line in this function adds an empty key-value pair variant to the `users` variant which should be intialized to a `list` type.

### Getting Values

#### Getting Primitive Values

Getting the values out of the variant can be done in two different ways:

1. Using macro `amxc_var_constcast`
2. Using macro `amxc_var_dyncast`

Both will retrieve the value of the variant, the difference is that `amxc_var_dyncast` will do [conversion](#conversions) if needed and allocate memory if needed, while `amxc_var_constcast` will return the stored value that is in the variant as `const` if it is a pointer.

As `amxc_var_constcast` is never doing any conversions, it will return the default value of the requested type if the type contained in the variant is different.

Some examples:

- The variant contains a string and an integer is requested.

    ```C
    amxc_var_t my_var;
    amxc_var_init(&my_var);
    amxc_var_set(cstring_t, &my_var, "1234");

    int32_t number = amxc_var_constcast(uint32_t, &my_var); // number will be 0
    int32_t number = amxc_var_dyncast(uint32_t, &my_var); // number will be 1234
    ```

- The variant contains a boolean and a string is requested

    ```C
    amxc_var_t my_var;
    amxc_var_init(&my_var);
    amxc_var_set(bool, &my_var, true);

    const char *txt = amxc_var_constcast(cstring_t, &my_var); // txt will be NULL
    char *txt = amxc_var_dyncast(cstring_t, &my_var); // txt will be "true", txt must be freed when not needed anymore
    ```

#### Getting Composite Values

##### Accessing Individual Primitives

Getting the individual values out of a composite variant can be done by accessing the individual variant by it's `path`.

The function to retrieve a primitive variant out of the composite variant is:

```C
amxc_var_t *amxc_var_get_path(const amxc_var_t * const var,
                              const char * const path,
                              const int flags);
```

This function will give the pointer to the variant as in the composite variant or a newly allocated variant, which you need to free with `amxc_var_delete`. The `flags` argument is used to indicate what you want the variant as is or a copy. The flags can be:

- AMXC_VAR_FLAG_DEFAULT (no copy, use the variant as is)
- AMXC_VAR_FLAG_COPY (allocate a new variant, and copy the data)

> NOTE
>
> When using the default behavior `AMXC_VAR_FLAG_DEFAULT` the pointer to the variant in the composite variant is returned. When changing the value of that returned value, the value in the composite variant is changed.

Example:

Let's take the `users` data set (see [Setting Composite Values](#setting-composite-values)) and assume a complex variant is created with this data (JSON notation)

```json
[
    {
        "user_id": 1,
        "name": "John Doe",
        "access_rights": 0x775
    },
    {
        "user_id": 2,
        "name": "Jane Doe",
        "access_rights": 0x664
    },
    {
        "user_id": 3,
        "name": "Super",
        "access_rights": 0x777
    }
]
```

Getting the name of the second user in the composite variant can be achieved by:

```C
amxc_var_t *var_name = amxc_var_get_path(&users, "1.name", AMXC_VAR_FLAG_DEFAULT);
const char *str_name = amxc_var_constcast(cstring_t, var_name);
```

A list can be accessed using an index, the first element in a list will have index 0. Key-value pairs can be accessed by key.

##### Accessing The List 

When a variant contains a `list` type, the pointer to the linked list in the variant can be fetch using the macro `amxc_var_constcast`. 

```C
const amxc_llist_t *var_list = amxc_var_constcast(amxc_llist_t, &my_var);
```

Use the `amxc_llist_t` API to access or iterate over the list. Each item in the list will be a variant. Use function `amxc_var_from_llist_it` to get the variant pointer.

##### Accessing The Hash Table

When a variant contains a `htable` type, the pointer to the hash table in the variant can be fetch using the macro `amxc_var_constcast`. 

```C
const amxc_htable_t *var_table = amxc_var_constcast(amxc_htable_t, &my_var);
```

Use the `amxc_htable_t` API to access or iterate over the hash table. Each item in the table will be a variant. Use function `amxc_var_from_htable_it` to get the variant pointer.

##### Iterating A Composite List

A composite variant containing a list of variants can be iterated using macro `amxc_var_for_each`

Example:

```C
amxc_var_for_each(user, (&users)) {
    amxc_var_t *var_name = amxc_var_get_path(user, "name", AMXC_VAR_FLAG_DEFAULT);
    const char *str_name = amxc_var_constcast(cstring_t, var_name);
}
```

> NOTE 
>
> Iterating only works on composite list variants and not on composite key-value pair variants.

### Inspecting The Content

With very complex composite variants it can be difficult to understand what is stored in the variant. A debug function is available that will print the content of the variant in a JSON like structure. 

```C
int amxc_var_dump(const amxc_var_t * const var, int fd);
```

The file descriptor can be STDOUT_FILENO, STDERR_FILENO or any other file descriptor with write permissions.

Example output (using the `users` example)

```txt
[
    {
        user_id: 1,
        name: "John Doe",
        access_rights: 0x775
    },
    {
        user_id: 2,
        name: "Jane Doe",
        access_rights: 0x664
    },
    {
        user_id: 3,
        name: "Super",
        access_rights: 0x777
    }
]
```

### Concatenation, merging, appending

Given two variants `var1` and `var2`, we can add `var2` to `var1` by calling `amxc_var_add_value(var1, var2)`. The result is stored in `var2`.

If `var1` and `var2` are both list variants, all elements of `var2` will be added to `var1`.
For example:

```c
#include <amxc/amxc.h>
int main() {
    amxc_var_t list1;
    amxc_var_t list2;
    amxc_var_init(&list1);
    amxc_var_init(&list2);
    amxc_var_set_type(&list1, AMXC_VAR_ID_LIST);
    amxc_var_set_type(&list2, AMXC_VAR_ID_LIST);

    // list1 = [2, 3, 5, 7]
    amxc_var_add(int32_t, &list1, 2);
    amxc_var_add(int32_t, &list1, 3);
    amxc_var_add(int32_t, &list1, 5);
    amxc_var_add(int32_t, &list1, 7);

    // list2 = [11, 13, 17, 19]
    amxc_var_add(int32_t, &list2, 11);
    amxc_var_add(int32_t, &list2, 13);
    amxc_var_add(int32_t, &list2, 17);
    amxc_var_add(int32_t, &list2, 19);

    // list1 += list2
    // (for brevity, this example does not do error handling)
    amxc_var_add_value(&list1, &list2);

    // print list1
    amxc_var_dump(&list1, STDOUT_FILENO);

    amxc_var_clean(&list1);
    amxc_var_clean(&list2);

    return 0;
}
```
```console
$ gcc -Wall -Wextra -Werror main.c -lamxc -o main
$ ./main
[
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19
]
$ 
```

The exact operation performed by `amxc_var_add_value` depends on the type of `var1`:
- lists: list concatenation.<br/>
  Example: see C example above.
- htables: table merging. If both tables use the same key, the resulting table maps the key to the value that `var2` maps the key to.<br />
  Example: if `var1` contains `{"monday": "sunny", "tuesday": "rainy", "wednesday": "snow"}` and `var2` contains `{"wednesday": "hail", "friday": "sunny"}`, then after `amxc_var_add_value(&var1, &var2)` we have that `var1` contains `{"monday": "sunny", "tuesday": "rainy", "wednesday": "hail", "friday": "sunny"}`.
- strings: string concatenation.<br />
  Example: if `var1` contains `"hello "` and `var2` contains `"world"`, then after `amxc_var_add_value(&var1, &var2)` we have that `var1` contains `"hello world"`.
- integers: integer addition.<br />
  Example: if `var1` contains `1` and `var2` contains `2`, then after `amxc_var_add_value(&var1, &var2)` we have that `var1` contains `3`.

If `var2` is of a different type than `var1`, then `var2` is converted to the type of `var1` before
performing the operation. This is the same [conversion](#conversions) as performed by `amxc_var_convert`. For example, if `var1` contains the string `"hello "` and `var2` contains the integer `1234`, then after `amxc_var_add_value(&var1, &var2)` we have that `var1` contains the string `"hello 1234"`.

## Conversions

<!-- THE TABLE BELOW IS AUTOGENERATED by test_amxc_var_conversion_table.c - please do not edit by hand -->
|↓to→|null|str |i8 |i16 |i32 |i64 |u8 |u16 |u32 |u64 |f32 |f64 |bool|list|htable|fd |ts  |csv |ssv |
|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
|null|⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |⛔   |
|str |✅!  |✅   |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |✅!  |✅!  |⛔   |🟠!  |✅   |✅   |
|i8 |✅!  |✅   |✅   |✅   |✅   |✅   |✅!  |✅!  |✅!  |✅!  |✅!  |✅   |✅!  |✅!  |✅!  |🟠   |✅!  |✅   |✅   |
|i16 |✅!  |✅   |🟠   |✅   |✅   |✅   |🟠!  |✅!  |✅!  |✅!  |✅!  |✅   |✅!  |✅!  |✅!  |🟠   |✅!  |✅   |✅   |
|i32 |✅!  |✅   |🟠   |🟠   |✅   |✅   |🟠!  |🟠!  |✅!  |✅!  |✅!  |✅   |✅!  |✅!  |✅!  |🟠   |✅!  |✅   |✅   |
|i64 |✅!  |✅   |🟠   |🟠   |🟠   |✅   |🟠!  |🟠!  |🟠!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |🟠   |🟠   |✅   |✅   |
|u8 |✅!  |✅   |🟠   |✅   |✅   |✅   |✅   |✅   |✅   |✅   |✅!  |✅   |✅!  |✅!  |✅!  |🟠   |✅!  |✅   |✅   |
|u16 |✅!  |✅   |🟠   |🟠   |✅   |✅   |🟠   |✅   |✅   |✅   |✅!  |✅   |✅!  |✅!  |✅!  |🟠   |✅!  |✅   |✅   |
|u32 |✅!  |✅   |🟠   |🟠   |🟠   |✅   |🟠   |🟠   |✅   |✅   |✅!  |✅   |✅!  |✅!  |✅!  |🟠   |✅!  |✅   |✅   |
|u64 |✅!  |✅!  |🟠   |🟠   |🟠   |🟠   |🟠   |🟠   |🟠   |✅   |✅!  |✅!  |✅!  |✅!  |✅!  |🟠   |🟠!  |✅!  |✅!  |
|f32 |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |?   |
|f64 |✅!  |✅!  |🟠   |🟠   |🟠   |🟠   |🟠!  |🟠!  |🟠!  |🟠!  |✅!  |✅   |✅!  |✅!  |✅!  |⛔   |⛔   |✅!  |✅!  |
|bool|✅!  |✅   |✅   |✅   |✅   |✅   |✅   |✅   |✅   |✅   |✅!  |✅   |✅   |✅!  |✅!  |⛔   |⛔   |✅   |✅   |
|list|✅!  |✅!  |🟠!  |✅!  |✅!  |✅!  |🟠!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |⛔   |⛔   |✅!  |✅!  |
|htable|✅!  |🟠!  |🟠!  |✅!  |✅!  |✅!  |🟠!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |⛔   |⛔   |🟠!  |🟠!  |
|fd |✅!  |✅!  |🟠   |🟠   |✅!  |✅!  |🟠   |🟠   |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅!  |✅   |⛔   |✅!  |✅!  |
|ts  |✅!  |✅   |⛔   |⛔   |⛔   |✅!  |⛔   |⛔   |⛔   |⛔   |⛔   |✅!  |⛔   |✅!  |✅!  |⛔   |✅   |✅   |✅   |
|csv |✅!  |✅   |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |✅!  |✅!  |⛔   |🟠!  |✅   |✅   |
|ssv |✅!  |✅   |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |🟠!  |✅!  |✅!  |⛔   |🟠!  |✅   |✅   |
<!-- THE TABLE ABOVE IS AUTOGENERATED by test_amxc_var_conversion_table.c - please do not edit by hand -->

- ✅ : All values can be converted
- 🟠 : Some values can be converted and some cannot
- ⛔ : No values can be converted
- ! : converting back does not always yield the same value (according to `amxc_var_compare`)

The table above shows for each type (row) to which type (column) it can convert to using `amxc_var_convert`. Values that are impractically big are not taken into account in this table, i.e. a list, hastable, or string of more than 66000 elements or characters.

Conversion from signed to unsigned integers drop the sign, for example converting int8 -1 to uint8 yields 1. If an integral conversion does not fit, then conversion fails, for example converting 700 to int8 fails.