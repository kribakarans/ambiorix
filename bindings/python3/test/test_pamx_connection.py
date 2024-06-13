#!/usr/bin/env pytest3
""" Testing python amx bindings data model interactions via connections.
"""
import time
import pytest
import pamx


def error_list_callback(data):
    """ Callback function which will raise an exception"""
    if data is not None:
        if safe_list_get(data, 0, None) == "Phonebook.Contact.1.":
            raise pamx.PAMXError("Callback exception")


def test_add_instance(connection):
    """Test to see if adding an instance is possible."""
    added = connection.add(
        "Phonebook.Contact.", {
            "FirstName": "John", "LastName": "Doe"})
    path = added[0]["path"]
    contact = connection.get(path)
    assert contact[0][path]["FirstName"] == "John"
    assert contact[0][path]["LastName"] == "Doe"


def test_add_instance2(connection):
    """Test to see if adding an indexed instance is possible."""
    connection.add(
        "Phonebook.Contact.", {
            "FirstName": "John", "LastName": "Doe"}, 123)
    path = "Phonebook.Contact.123."
    contact = connection.get(path)
    assert contact[0][path]["FirstName"] == "John"
    assert contact[0][path]["LastName"] == "Doe"


def test_get_scall(connection):
    """ Perform get with a function call"""
    path = "Phonebook.Contact.123."
    contact = connection.call(path, "_get")
    assert contact[0][path]["FirstName"] == "John"
    assert contact[0][path]["LastName"] == "Doe"


def test_call_failure(connection):
    """ Perform call with incorrect parameters which will raise an error."""
    path = "Phonebook.Contact.123."
    with pytest.raises(pamx.AMXError):
        connection.call(path, "WrongFunction")


def test_call_incorrect_parameters(connection):
    """ Perform call with incorrect parameters which will raise an error."""
    path = "Phonebook.Contact.123."
    with pytest.raises(pamx.AMXError):
        connection.call(path)


def test_get_incorrect_parameters(connection):
    """ Perform get with parameters that should raise an error"""
    with pytest.raises(pamx.AMXError):
        connection.get()


def test_set_scall(connection):
    """ Perform set with a function call"""
    path = "Phonebook.Contact.123."
    connection.call(path, "_set", {"parameters": {"FirstName": "Jane"}})
    contact = connection.call(
        "Phonebook.Contact.123.", "_get", {
            "parameters": ["FirstName"]}, 10)
    assert contact[0][path]["FirstName"] == "Jane"


def test_set_failure(connection):
    """ Perform set on a non existing object which will raise an error."""
    with pytest.raises(pamx.AMXError):
        path = "Phonebook.Contact.DoesNotExist."
        connection.set(path, {"FirstName": "Jane"})


def test_set_incorrect_parameters(connection):
    """ Perform set with incorrect parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.set()


def test_add_instance3(connection):
    """Test to see if adding a named instance is possible."""
    connection.add(
        path="Phonebook.Contact.",
        values={
            "FirstName": "John",
            "LastName": "Doe"},
        name="NamedContact")
    path = "Phonebook.Contact.NamedContact."
    index = connection.describe(path)[0]["index"]
    index_path = f"Phonebook.Contact.{index}."
    contact = connection.get(path)
    assert contact[0][index_path]["FirstName"] == "John"
    assert contact[0][index_path]["LastName"] == "Doe"


def test_add_failure(connection):
    """ Perform add with a name that is not unique which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.add(
            path="Phonebook.Contact.NamedContact.",
            values={
                "FirstName": "John",
                "LastName": "Doe"},
            name="NamedContact")


def test_add_incorrect_parameters(connection):
    """ Perform add with incorrect parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.add()


def test_set_instance(connection):
    """Test to see if writable parameters of an object can be set."""
    path = "Phonebook.Contact.NamedContact."
    connection.set(path, {"FirstName": "Jane"})
    contact = connection.get(path)
    path = "Phonebook.Contact.NamedContact."
    index = connection.describe(path)[0]["index"]
    index_path = f"Phonebook.Contact.{index}."
    assert contact[0][index_path]["FirstName"] == "Jane"
    assert contact[0][index_path]["LastName"] == "Doe"


def test_del_instance(connection):
    """ Test to delete an instance """
    path = "Phonebook.Contact.NamedContact."
    assert not [{}] == connection.get(path)
    connection.delete(path)
    with pytest.raises(pamx.AMXError):
        connection.get(path)


def test_del_failure(connection):
    """ Perform delete on a template object which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.delete("Phonebook.")


def test_del_non_existing_instance(connection):
    """ Perform delete on an instance that doesn't exist which not raise an error."""
    path = "Phonebook.Contact.NamedContact."
    with pytest.raises(pamx.AMXError):
        connection.get(path)
    with pytest.raises(pamx.AMXError):
        connection.delete(path)


def test_del_incorrect_parameters(connection):
    """ Perform delete with incorrect parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.delete()


def test_describe(connection):
    """Test describe method"""
    description = connection.describe(
        "Phonebook.Contact.123.",
        functions=1,
        objects=1,
        parameters=1,
        instances=1)
    assert len(description[0]["parameters"]) == 3


def test_describe_failure(connection):
    """ Perform describe on an object that doesn't exist which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.describe("Does.Not.Exist")


def test_describe_incorrect_parameters(connection):
    """ Perform describe with incorrect parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.describe()


def test_get_supported(connection):
    """Test get_supported method"""
    supported = connection.get_supported(
        "Phonebook.Contact.",
        first_level=1,
        functions=1,
        parameters=1,
        events=1)
    assert len(supported[0]["Phonebook.Contact.{i}."]["supported_params"]) == 3
    assert supported[0]["Phonebook.Contact.{i}."]["is_multi_instance"]


def test_get_supported_on_non_existing_instance(connection):
    """ Perform get_supported on an instance that does not exist which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.get_supported("Phonebook.Contact.DoesNotExist.")


def test_get_supported_incorrect_parameters(connection):
    """ Perform get_supported with incorrect parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.get_supported()


def test_connection_disconnect():
    """Test to see if connections can be closed"""
    connection = pamx.bus.connect("pcb:/tmp/local")
    supported = connection.get_supported(
        "Phonebook.Contact.",
        first_level=1,
        functions=1,
        parameters=1,
        events=1)
    assert len(supported[0]["Phonebook.Contact.{i}."]["supported_params"]) == 3
    assert supported[0]["Phonebook.Contact.{i}."]["is_multi_instance"]

    connection.close()
    with pytest.raises(pamx.AMXError):
        connection.get_supported(
            "Phonebook.Contact.",
            first_level=1,
            functions=1,
            parameters=1,
            events=1)


def safe_list_get(list_obj, idx, default):
    """Retrieve item for list or default if index doesn't exist"""
    try:
        return list_obj[idx]
    except IndexError:
        return default


def list_handler(data):
    """ callback function for list handler """
    if data is not None:
        if safe_list_get(data, 0, None) == "Phonebook.Contact.1.":
            assert "Phonebook.Contact.1.FirstName" in data
            assert "Phonebook.Contact.1.LastName" in data
            pamx.eventloop.stop()


def test_list(connection):
    """ Test list method"""
    connection.list(
        "Phonebook.Contact.",
        list_handler,
        functions=1,
        parameters=1,
        objects=1,
        instances=1)
    pamx.eventloop.start()


def list_handler_with_userdata(data, params):
    """ callback function for list handler """
    if data is not None:
        assert data.sort() == params.sort()
        pamx.eventloop.stop()


def test_list_with_userdata(connection):
    """ Test list method with userdata"""
    param_list = [
        "Phonebook.Contact.1.FirstName",
        "Phonebook.Contact.1.LastName"]
    connection.list(
        "Phonebook.Contact.1.",
        list_handler_with_userdata,
        param_list,
        functions=0,
        parameters=1,
        objects=0,
        instances=0)
    pamx.eventloop.start()


def test_list_failure(connection):
    """ Perform describe on an object that does not exist which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.list("Does.Not.Exist", list_handler)


def test_list_incorrect_parameters(connection):
    """ Perform list with incorrect parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.list()


def test_list_incorrect_parameters2(connection):
    """ Perform list with handler on an object that does not exist which will raise an error."""
    with pytest.raises(TypeError):
        connection.list("Does.Not.Exist.", "list_handler")


def test_list_callback_failure(connection):
    """ Perform list with a callback function which will raise an error."""
    with pytest.raises(Exception):
        connection.list(
            "Phonebook.Contact.",
            error_list_callback,
            functions=1,
            parameters=1,
            objects=1,
            instances=1)
        pamx.eventloop.start()


def test_async_call(connection):
    """ Perform an asynchronous add."""
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.ASYNC.")
    request = connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "ASYNC"})
    time.sleep(1)
    request.wait()
    request.close()
    assert not [{}] == connection.get("Phonebook.Contact.ASYNC.")


def test_async_call_auto_close(connection):
    """ Test to check if a request automatically closes when it goes out of scope"""
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.ASYNCCLOSE.")
    request = connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "ASYNCCLOSE"})
    request.wait()
    assert not [{}] == connection.get("Phonebook.Contact.ASYNCCLOSE.")


ASYNC_HANDLER_CALLED = False


# pylint: disable=global-statement
def async_handler(retval):
    """ Async request handler"""
    assert retval[0]["object"] == "Phonebook.Contact.ASYNC2."
    global ASYNC_HANDLER_CALLED
    ASYNC_HANDLER_CALLED = True


# pylint: disable=global-statement
def test_async_call_handler(connection):
    """ Perform an asynchronous add with a callback function."""
    assert not ASYNC_HANDLER_CALLED
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.ASYNC2.")
    request = connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "ASYNC2"}, async_handler)
    request.wait(5)
    assert not [{}] == connection.get("Phonebook.Contact.ASYNC2.")
    assert ASYNC_HANDLER_CALLED


def test_async_call_handler_timeout(connection):
    """ Perform an asynchronous add of an existing instance which will timeout."""
    connection.get("Phonebook.Contact.ASYNC2.")
    request = connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "ASYNC2"}, async_handler)
    with pytest.raises(pamx.AMXError):
        request.wait(5)


def async_handler_userdata(retval, userdata):
    """ Async request handler with userdata"""
    assert retval[0]["object"] == userdata


def test_async_call_handler2(connection):
    """ Perform an asynchronous add with a callback function and user data."""
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.ASYNC3")
    request = connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "ASYNC3"}, async_handler_userdata, "Phonebook.Contact.ASYNC3.")
    request.wait()
    connection.get("Phonebook.Contact.ASYNC3.")


def test_async_call_close_request_twice(connection):
    """ Test if calling close on an already closed request raises an exception."""
    request = connection.async_call(
        "Phonebook.Contact.", "_get", {
            "name": "ASYNC3"})
    request.close()
    with pytest.raises(pamx.AMXError):
        request.close()


def test_async_call_wait_for_closed_request(connection):
    """ Test if calling wait on an already closed request raises an exception."""
    request = connection.async_call(
        "Phonebook.Contact.", "_get", {
            "name": "ASYNC3"})
    request.close()
    with pytest.raises(pamx.AMXError):
        request.wait()


def test_async_call_error_in_handler(connection):
    """ Perform an asynchronous add with a callback function which will raise an error."""
    with pytest.raises(pamx.AMXError):
        request = connection.async_call(
            "Phonebook.Contact.", "_add", {
                "name": "ASYNC3"}, async_handler_userdata, "Phonebook.Contact.ASYNC3.")
        request.wait()


def test_async_call_incorrect_parameters(connection):
    """ Perform an asynchronous add on a template that doesn't exist which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.async_call("Does.Not.Exist.", "_get")


def test_async_call_incorrect_parameters2(connection):
    """
    Perform an asynchronous get without a callback function,
    but with userdata which will raise an error.
    """
    with pytest.raises(pamx.AMXError):
        connection.async_call(
            "Phonebook.", "_get", userdata={
                "param": "value"})


def test_async_call_incorrect_parameters3(connection):
    """ Perform an asynchronous get without a non callable value for the callback function,
    which will raise an error.
    """
    with pytest.raises(TypeError):
        connection.async_call(
            "Phonebook.", "_get", callback="async_handler")


def test_async_call_incorrect_parameters4(connection):
    """ Perform an asynchronous get without parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.async_call()


def test_async_request_wait_error(connection):
    """ Incorrect wait call"""
    request = connection.async_call("Phonebook.Contact.", "_get")
    with pytest.raises(pamx.AMXError):
        request.wait("test")
