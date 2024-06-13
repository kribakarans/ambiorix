# Linked List Contacts Example

[[_TOC_]]

## Introduction

The contacts example exist in three different implementations. One to demonstrate the **libamxc llist** API, one to demonstrate the **libamxc htable** API and one to demonstrate the **libamxc variants** API. Here the llist (linked list) implementation is threated. The recommended way to study these examples is the following:
- llist_contacts (this example)
- [htable_contacts](https://gitlab.com/soft.at.home/ambiorix/ambiorix/examples/collections/htable_contacts/) 
- [variant_contacts](https://gitlab.com/soft.at.home/ambiorix/ambiorix/examples/collections/variant_contacts)

The goal of these examples is to to demonstrate:
- How to use the llist, htable and variant API.
- What the difference is between a llist, htable and variant implementation.

The goal of these examples is not to explain in detail how the APIs itself are implemented.

This readme will guide you step by step through the linked list example.

### What is a linked list?

>In computer science, a linked list is a linear collection of data elements whose order is not given by their physical placement in memory. Instead, each element points to the next. It is a data structure consisting of a collection of nodes which together represent a sequence. In its most basic form, each node contains: data, and a reference (in other words, a link) to the next node in the sequence. In a doubly linked list each node contains three fields: two link fields (references to the previous and to the next node in the sequence of nodes) and one data field.  ~ [Wikipedia](https://en.wikipedia.org/wiki/Linked_list)

The **libamxc llist** is a doubly linked list.

The advantages of a linked list are:
- Elements can be added infinitely
- A linked list only takes memory for the items in the list (and not for empty spaces)
- Elements are easily removed

A linked list has also his disadventages:
- No random access to elements (only sequential access)
- A linked list takes more space per item compared to an array (data + reference to next item)

Taking this adventages and disadventages into account, it should be clear that linked lists should be used for data collections where the number of items is (very) dynamic.

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

- [libamxc](https://gitlab.com/soft.at.home/ambiorix/ambiorix/libraries/libamxc) - Generic C api for common data containers

#### Build llist_contacts

1. Clone the git repository

    To be able to build it, you need the source code. So open the directory just created for the ambiorix project and clone this library in it.

    ```bash
    cd ~/amx_project/examples/collections
    git clone https://gitlab.com/soft.at.home/ambiorix/examples/collections/llist_contacts.git
    ``` 

1. Install dependencies

    Although the container will contain all tools needed for building, it does not contain the libraries needed for building `llist_contacts`. To be able to build `llist_contacts` you need `libamxc`. This library can be installed in the container.

    ```bash
    sudo apt update
    sudo apt install libamxc
    ```

    If you would like to build and install the library manually, you can follow the instructions on the [libamxc repo page](https://gitlab.com/soft.at.home/ambiorix/ambiorix/libraries/libamxc).

1. Build it

    After the variable is set, you can build the package.

    ```bash
    cd ~/amx_project/examples/collections/llist_contacts
    make
    ```

### Testing

#### Prerequisites

No extra components are needed for testing `llist_contacts`.

#### Run tests

You can run the tests by executing the following command.

```bash
cd ~/amx_project/examples/collections/llist_contacts/tests
make
```

Or this command if you also want the coverage reports to be generated:

```bash
cd ~/amx_project/examples/collections/llist_contacts/tests
make run coverage
```

#### Coverage reports

The coverage target will generate coverage reports using [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) and [gcovr](https://gcovr.com/en/stable/guide.html).

A summary for each file (*.c files) is printed in your console after the tests are run.
A HTML version of the coverage reports is also generated. These reports are available in the output directory of the compiler used.
Example: using native gcc
When the output of `gcc -dumpmachine` is `x86_64-linux-gnu`, the HTML coverage reports can be found at `~/amx_project/examples/collections/llist_contacts/output/x86_64-linux-gnu/coverage/report.`

You can easily access the reports in your browser.
In the container start a python3 http server in background.

```bash
cd ~/amx_project/
python3 -m http.server 8080 &
```

Use the following url to access the reports `http://<IP ADDRESS OF YOUR CONTAINER>:8080/examples/collections/llist_contacts/output/<MACHINE>/coverage/report`
You can find the ip address of your container by using the `ip` command in the container.

Example:

```bash
USER@<CID>:~/amx_project/examples/collections/llist_contacts$ ip a
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
So the uri you should use is: `http://172.17.0.7:8080/examples/collections/llist_contacts/output/x86_64-linux-gnu/coverage/report/`

## Using llist_contacts

As soon as you've build the source code, you can run the program using the following command.

```bash
cd ~/amx_project/examples/collections/llist_contacts
./llist_contacts data/randomdata.csv "Elliott"
```

`"Elliott"` is the last name of the contact/family you are searching for.

The output is in this case:

```bash
Person : Violet Elliott
	Gender = Female
	Age    = 25
	E-Mail = v.elliott@randatmail.com
	Phone  = 896-3242-73
	Status = Married

Person : James Elliott
	Gender = Male
	Age    = 23
	E-Mail = j.elliott@randatmail.com
	Phone  = 412-8887-99
	Status = Married

Person : Max Elliott
	Gender = Male
	Age    = 25
	E-Mail = m.elliott@randatmail.com
	Phone  = 406-1711-61
	Status = Married

Person : Thomas Elliott
	Gender = Male
	Age    = 22
	E-Mail = t.elliott@randatmail.com
	Phone  = 367-6904-83
	Status = Married


Matches found = 4
```

## Code explanation

The first thing to explain is how we will represent a single person. In `/include_prev/contacts.h` you can find the following declaration:

```C
typedef struct person {
    char* first_name;
    char* last_name;
    gender_t gender;
    uint32_t age;
    char* email;
    char* phone;
    marital_status_t mstatus;
    amxc_llist_it_t it;
} person_t;
```

You can find all characteristics of the person plus an `amxc_llist_it_t` type 'it'. This iterator contains the link to the next and previous item in the linked list. In this case the iterator points towards the next and previous iterator in the linked list.

We will go step by step through the `main.c` code to make the use of the linked list API clear.

The first step is to define a linked list. Here we create a linked list called 'contacts'.

```C
amxc_llist_t contacts;
```

After we created a linked list, we should initialize it.

```C
contacts_init(&contacts);
```

If we look to the implementation of the `contacts_init()` function, we see that the only thing it does is calling this function:

```C
amxc_llist_init()
```

The `amxc_llist_init()` function is typically used for linked list that are defined on the stack. If you would like to define a linked list on the heap, you should use the `amxc_llist_new()` function instead.

The following line is the most important one of this example.

```C
contacts_read(&contacts, argv[1], 1);
```

The `contacts_read()` function loops over each line of our file `/data/randomdata.csv` and places each contact in the linked list 'contacts'. We will dive into this function right now.

At the top of the `contacts_read()` function we see again the declaration of a linked list.

```C
amxc_llist_t fields;
```

This list is used to store the data of one single person (first name, last name, age, ...). The details on how this is actually done is not of importance here.

Near the middle of this function we can see the `person_new()` function:

```C
person_new(&person_data, &fields)
```

Here memory is allocated on the heap to store the 'person_data'. Then the new allocated structure is filled with the data stored in the 'fields' linked list. The order of the fields is for each person exactly the same (as defined in the data file), so the fields can be taken from the linked list in that order.

To summerize: we have read out a line of the `/data/randomdata.csv` file and stored this line in the linked list 'fields'. Then, we stored this information in a struct 'person_data'.

The only thing that's left to do is adding this 'person_data' to our linked list 'contacts'. That's exactly what is done near the end of the function `contacts_read()`:

```C
 contacts_add_person(contacts, person_data);
```

The only thing that the `contacts_add_person()` function does is calling the function `amxc_llist_append()`. This function is typically used to add some data to a linked list.

```C
amxc_llist_append(contacts, &person->it);
```

This is the first part of our application. We have now a linked list containing all data of our data file. Next thing to do is search for a specific contact/family.

This is implemented in the `contacts_search()` function. If we dive into this function we see that if we enter this function for the first time, we call:

```C
 amxc_llist_get_first(contacts)
```

This function returns the adress of the first iterator of a linked list.

If there are multiple contacts with the same last name, we will get multiple times into this `contacts_search()` function. The second time we will end up using the `amxc_llist_it_get_next()` function.

```C
amxc_llist_it_get_next(&reference->it)
```

As an input you give the iterator of a certain item in the linked list. The function returns you the adress of the iterator of the next item in the linked list. 

If we have the iterator of an item in the linked list, we need to be able to get the data belonging to this item. This is done with the `amxc_llist_it_get_data()` function.

```C
amxc_llist_it_get_data(it, person_t, it);
```

The first argument is the address of your iterator, the second argument the data type of which your iterator is part of (a structure), and the last argument is the structure member name of the iterator in the structure.

Note that for the linked list, we need to loop over our list and check element by element if this is the searched one. Searching in a big list can be time expensive for this reason.

The last thing to do is to clean our 'contacts' linked linst. This is done with the `contacts_clean()` funcion.

```C
contacts_clean(&contacts);
```

The contacts clean function calls the `amxc_llist_clean()` function.

```C
amxc_llist_clean(contacts, contact_clean);
```

This function will loop over your linked list items and remove all iterators. For a linked list defined on the heap you should use the `amxc_llist_delete()` function. The only thing we need to do ourself is to remove all memory space we allocated for storing our contacts information. This is why the seconds argument of this function is a function itself. The `contact_clean()` function will free all our allocated memory space.

```C
static void contact_clean(amxc_llist_it_t* it) {
    person_t* person = amxc_llist_it_get_data(it, person_t, it);
    person_del(&person);
}
```

The freeing itself happens in the `person_del()` function.