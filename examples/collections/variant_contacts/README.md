# Variant Contacts Example

## Introduction

The contacts example exist in three different implementations. One to demonstrate the **libamxc llist** API, one to demonstrate the **libamxc htable** API and one to demonstrate the **libamxc variants** API. Here the variant implementation is threated. The recommended order to study these examples is the following:
- [llist_contacts](https://gitlab.com/soft.at.home/ambiorix/ambiorix/examples/collections/llist_contacts/)
- [htable_contacts](https://gitlab.com/soft.at.home/ambiorix/ambiorix/examples/collections/htable_contacts/)
- variant_contacts (this example)

The goal of these examples is to demonstrate:
- How to use the llist, htable and variant API.
- What the difference is between a llist, htable and variant implementation.

The goal of these examples is not to explain in detail how the APIs itself are implemented.

This readme will guide you step by step through the variant example.

### What is a variant?

> In computer science, a tagged union, also called a variant, variant record, choice type, discriminated union, disjoint union, sum type or coproduct, is a data structure used to hold a value that could take on several different, but fixed, types. Only one of the types can be in use at any one time, and a tag field explicitly indicates which one is in use. It can be thought of as a type that has several "cases", each of which should be handled correctly when that type is manipulated. This is critical in defining recursive datatypes, in which some component of a value may have the same type as the value itself, for example in defining a type for representing trees, where it is necessary to distinguish multi-node subtrees and leafs. Like ordinary unions, tagged unions can save storage by overlapping storage areas for each type, since only one is in use at a time. ~[Wikipedia](https://en.wikipedia.org/wiki/Tagged_union)

The **Ambiorix variant data container** is a tagged union and can contain many different types, each variant can hold only one data type at a given point in time.

For more information about the **Ambiorix variant data container** you can check the specific [variant documentation](https://gitlab.com/soft.at.home/ambiorix/libraries/libamxc/-/blob/main/doc/variant.md).

### Contacts example

Before we can start, we should give a brief overview of what our example application is supposed to do.

The goal of our application is to store a list of contacts. These contacts are imported from the file `/data/randomdata.csv` and contains the following information about a person:
- First Name
- Last Name
- Gender
- Age
- Email
- Phone
- Marital Status

We should be able to search a contact by his last name. If multiple contacts share the same last name, we call them a family. The program should always output the whole family.

## Building and testing

You could install all tools needed for testing and developing on your local machine, but it is easier to just use a pre-configured environment. Such an environment is already prepared for you as a docker container.

1. Install docker

    Docker must be installed on your system.

    If you have no clue how to do this here are some links that could help you:

    - [Get Docker Engine - Community for Ubuntu](https://docs.docker.com/install/linux/docker-ce/ubuntu/)
    - [Get Docker Engine - Community for Debian](https://docs.docker.com/install/linux/docker-ce/debian/)
    - [Get Docker Engine - Community for Fedora](https://docs.docker.com/install/linux/docker-ce/fedora/)
    - [Get Docker Engine - Community for CentOS](https://docs.docker.com/install/linux/docker-ce/centos/)  <br /><br />
    
    Make sure you user id is added to the docker group:

    ```
    sudo usermod -aG docker $USER
    ```

1. Fetch the container image

    To get access to the pre-configured environment, all you need to do is pull the image and launch a container.

    Pull the image:

    ```bash
    docker pull softathome/oss-dbg:latest
    ```

    Before launching the container, you should create a directory wich will be shared between your local machine and the container.

    ```bash
    mkdir -p ~/amx_project/examples/collections
    ```

    Launch the container:

    ```bash
    docker run -ti -d --name oss-dbg --restart always --cap-add=SYS_PTRACE --sysctl net.ipv6.conf.all.disable_ipv6=1 -e "USER=$USER" -e "UID=$(id -u)" -e "GID=$(id -g)" -v ~/amx_project/:/home/$USER/amx_project/ softathome/oss-dbg:latest
    ```

    The `-v` option bind mounts the local directory for the ambiorix project in the container, at the exact same place.
    The `-e` options create environment variables in the container. These variables are used to create a user name with exactly the same user id and group id in the container as on your local host (user mapping).

    You can open as many terminals/consoles as you like:

    ```bash
    docker exec -ti --user $USER oss-dbg /bin/bash
    ```

### Building

#### Prerequisites

- [libamxc](https://gitlab.com/soft.at.home/ambiorix/libraries/libamxc) - Generic C api for common data containers

#### Build variant_contacts

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it (on your local machine).

    ```bash
    cd ~/amx_project/examples/collections
    git clone https://gitlab.com/soft.at.home/ambiorix/examples/collections/variant_contacts.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `variant_contacts`. To be able to build `variant_contacts` you need `libamxc`. This library can be installed in the container.

    ```bash
    sudo apt update
    sudo apt install libamxc
    ```

    If you would like to build and install the library manually, you can follow the instructions on the [libamxc repo page](https://gitlab.com/soft.at.home/ambiorix/libraries/libamxc).

1. Build it

    ```bash
    cd ~/amx_project/examples/collections/variant_contacts
    make
    ```

### Testing

#### Prerequisites

No extra components are needed for testing `variant_contacts`.

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/examples/collections/variant_contacts/tests
make
```

Or this command if you also want the coverage reports to be generated:

```bash
cd ~/amx_project/examples/collections/variant_contacts/tests
make run coverage
```

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/examples/collections/variant_contacts/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/examples/collections/variant_contacts/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/amx_project/examples/collections/variant_contacts$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
173: eth0@if174: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:11:00:07 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.7/16 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2001:db8:1::242:ac11:7/64 scope global nodad 
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:7/64 scope link 
       valid_lft forever preferred_lft forever
```

in this case the ip address of the container is `172.17.0.7`.
So the uri you should use is: `http://172.17.0.7:8080/examples/collections/variant_contacts/output/x86_64-linux-gnu/coverage/report/`

## Using variant_contacts

As soon as you've build the source code, you can run the program using the following command.

```bash
cd ~/amx_project/examples/collections/variant_contacts
./variant_contacts data/randomdata.csv "Elliott"
```

`"Elliott"` is the last name of the contact/family you are searching for.

The output is in this case:

```bash
[
    {
        age = "22",
        email = "t.elliott@randatmail.com",
        first name = "Thomas"
        gender = "Male",
        last name = "Elliott",
        mstatus = "Married",
        phone = "367-6904-83",
    },
    {
        age = "25",
        email = "m.elliott@randatmail.com",
        first name = "Max"
        gender = "Male",
        last name = "Elliott",
        mstatus = "Married",
        phone = "406-1711-61",
    },
    {
        age = "23",
        email = "j.elliott@randatmail.com",
        first name = "James"
        gender = "Male",
        last name = "Elliott",
        mstatus = "Married",
        phone = "412-8887-99",
    },
    {
        age = "25",
        email = "v.elliott@randatmail.com",
        first name = "Violet"
        gender = "Female",
        last name = "Elliott",
        mstatus = "Married",
        phone = "896-3242-73",
    }
]

Matches found = 4
```

## Code explanation

First thing to do is to define a variant. 

```C
amxc_var_t* contacts = NULL;
```

Then we allocate some memory on the heap and set the variant type to the standard 'null' type.

```C
amxc_var_new(&contacts);
```

If you would like to allocate memory on the stack, you can use the `amxc_var_init()` function.

After the variant is initialized, we can set the variant type. We will use a hash table to store our contacts. 

```C
amxc_var_set_type(contacts, AMXC_VAR_ID_HTABLE);
```

The following line is the most important one of this example.

```C
contacts_read(contacts, argv[1], 1);
```

The `contacts_read()` function loops over each line of our file `/data/randomdata.csv` and places each contact in the 'contacts' variant (of type hash table). We will dive into this function right now.

At the top of the `contacts_read()` function we see the declaration of a linked list.

```C
amxc_llist_t fields;
```

This list is used to store the data of one single person (first name, last name, age, ...). The details on how this is actually done is not of importance here.

Near the middle of this function we can see the `person_new()` function:

```C
person_new(&person_data, &fields)
```

Here memory is allocated on the heap to store the `person_data`. 

```C
amxc_var_new(person);
```

After this, the 'person_data' variant is set to the type of hash table. For every person we will create a new hash table to store all his information (first name, last name, age, ...)

```C
amxc_var_set_type(*person, AMXC_VAR_ID_HTABLE);
```

Then the new allocated structure is filled with the data stored in the 'fields' linked list. The order of the fields is for each person exactly the same (as defined in the data file), so the fields can be taken from the linked list in that order.

If we look to the `person_set_field()` function, we can see that it calls:

```C
amxc_var_add_key(cstring_t, person, fname, amxc_string_get(field, 0));
```

This function is typically used to store data in variant of the type 'hash table'. The first argument defines the type of data you want to add, the second argument is your hash table key and the last argument is the data you want to add.

To summerize: we have read out a line of the `/data/randomdata.csv` file and stored this line in the linked list 'fields'. Then, we stored this information in a variant of type hash table 'person_data'.

The only thing that's left to do is adding this 'person_data' to our variant 'contacts' (also of the type hash table). That's exactly what is done near the end of the function `contacts_read()`:

```C
contacts_add_person(contacts, person_data);
```

The first thing to do is to know where we will store the person. We need his or her last name.

```C
const char* last_name = GET_CHAR(person, "last name");
```

The GET_CHAR is a macro for:

```C
amxc_var_constcast(cstring_t, amxc_var_get_key(person, "last name", AMXC_VAR_FLAG_DEFAULT))
```

The `amxc_var_get_key()` function returns the value which is stored with the key "last name". The `amxc_var_constcast()` function transforms this data to a string ('cstring_t').

Now we have the last name of the person we want to add to our hash table.

First thing to do is check if we have allready some members with this last name stored. We check in the 'contacts' variant for the key last_name.

```C
amxc_var_t* family = amxc_var_get_key(contacts, last_name, AMXC_VAR_FLAG_DEFAULT);
```

If there is not yet such a family, we want to create one. 

```C
family = amxc_var_add_key(amxc_llist_t, contacts, last_name, NULL);
```

The `amxc_var_add_key()` function is typically used to add data to a hash table. This time we add a variant of type linked list to our hash table.

After this, we want to add our person to the family variant.

```C
amxc_var_set_index(family, 0, person, AMXC_VAR_FLAG_DEFAULT);
```

Our person (which is a hash table variant) is now stored in a linked list (his family). This linked list is stored in the global hash table.

This is the first part of our application. We have now a hash table containing all data of our data file. Next thing to do is search for a specific contact/family.

This is implemented in the `contacts_search()` function. To get the data of our family, it simply calls:

```C
amxc_var_t* family = amxc_var_get_path(contacts, last_name, AMXC_VAR_FLAG_DEFAULT);
```

The `amxc_var_get_path()` function returns a pointer to the variant you are asking for. In this example we are asking for the linked list which is stored under the key 'last_name'. If we would call `amxc_var_get_path(contacts, last_name.1, AMXC_VAR_FLAG_DEFAULT)`, this would return the pointer to the variant storing the 2nd contact in the family. If we would call `amxc_var_get_path(contacts, last_name.1.age, AMXC_VAR_FLAG_DEFAULT)`, this would return the pointer to the variant storing the age of the 2nd contact in the family.

As soon as we have the pointer to the linked list variant containing the searched family, we need to convert this variant to a 'amxc_llist_t' in order to be able to use the `libamxc llist` API. 

```C
lresult = amxc_var_constcast(amxc_llist_t, search_result);
 ```

The variant API is offering a function you can call to print out his content.

```C
amxc_var_dump(search_result, STDOUT_FILENO);
```

Last thing to do is clearing the memory allocated by the variant. To clear all memory at once, we can simply call:

```C
amxc_var_delete(&contacts);
```

Note that in this example, we did not have to allocate memory ourself like in the `llist_contacts` or `htable_contacts` examples. All memory allocations are hidden in the `amxc_var_new()` function.