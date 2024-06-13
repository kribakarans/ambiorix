#!/usr/bin/env pytest3
""" Testing python amx bindings DMObjects.
"""
import pytest
import pamx


def safe_list_get(list_obj, idx, default):
    """Retrieve item for list or default if index doesn't exist"""
    try:
        return list_obj[idx]
    except IndexError:
        return default


def error_list_callback(data):
    """ Callback function which will raise an exception"""
    if data is not None:
        if safe_list_get(data, 0, None) == "Phonebook.Contact.1.":
            raise pamx.PAMXError("Callback exception")


def test_add_instance_dm_object():
    """Test to see if adding an instance is possible."""
    phonebook = pamx.DMObject("Phonebook.")
    assert phonebook.dmmngt.type_name == "singleton"
    contact_template = phonebook.dmmngt.objects()["Contact"]
    assert contact_template.dmmngt.type_name == "template"
    assert contact_template.dmmngt.__dict__["add"]
    contact_template.dmmngt.add({"name": "OBJECTTEST", "index": 456, "parameters": {
                                 "FirstName": "OBJECT", "LastName": "TEST"}})
    contact = pamx.DMObject("Phonebook.Contact.OBJECTTEST.")
    contact = contact_template.dmmngt.instances()["OBJECTTEST"]
    assert contact.dmmngt.type_name == "instance"
    assert contact.FirstName == "OBJECT"
    assert contact.LastName == "TEST"


def test_readonly_params():
    """ Test readonly property of parameters"""
    contact = pamx.DMObject("Phonebook.Contact.OBJECTTEST.")
    assert contact.Plugin == "PAMX"
    with pytest.raises(pamx.AMXError):
        contact.Plugin = "Test"
    assert contact.Plugin == "PAMX"


def test_dm_object_dir():
    """ Test DMObejct dir"""
    path = "Phonebook.Contact.456."
    contact_obj = pamx.DMObject(path)
    assert "FirstName" in dir(contact_obj)
    assert "LastName" in dir(contact_obj)


def test_get_scall_dm_object():
    """ Perform get with a function call"""
    path = "Phonebook.Contact.456."
    contact_obj = pamx.DMObject(path)
    contact = contact_obj.dmmngt.get()
    assert contact[0][path]["FirstName"] == "OBJECT"
    assert contact[0][path]["LastName"] == "TEST"


def test_get_scall_dm_object_failure():
    """
    Perform _get  of object with incompatible parameters.
    Params need to be a dictionary
    """
    path = "Phonebook.Contact.456."
    contact_obj = pamx.DMObject(path)
    with pytest.raises(pamx.AMXError):
        contact_obj.dmmngt.get(1)


def test_set_parameters_dm_object(connection):
    """Test to see if adding an instance is possible."""
    template = pamx.DMObject("Phonebook.Contact.")
    template.dmmngt.add({"name": "OBJECTTEST2", "index": 789, "parameters": {
                  "FirstName": "OBJECT", "LastName": "TEST"}})
    path = "Phonebook.Contact.789."

    contact = pamx.DMObject(path)
    assert contact.FirstName == "OBJECT"
    assert contact.LastName == "TEST"

    get = connection.get("Phonebook.Contact.789.LastName")
    assert get[0][path]["LastName"] == "TEST"

    contact.LastName = "TEST2"
    assert contact.LastName == "TEST2"
    get = connection.get("Phonebook.Contact.789.LastName")
    assert get[0][path]["LastName"] == "TEST2"

    named_contact = pamx.DMObject("Phonebook.Contact.OBJECTTEST2.")
    assert named_contact.LastName == "TEST2"
    named_contact.LastName = "TEST2_value2"
    get = connection.get("Phonebook.Contact.789.LastName")
    assert get[0][path]["LastName"] == "TEST2_value2"


def test_call_incorrect_parameters():
    """ Perform _set with no parameters which will raise an error."""
    path = "Phonebook.Contact.OBJECTTEST."
    contact = pamx.DMObject(path)
    with pytest.raises(pamx.AMXError):
        contact.dmmngt.set(1)


def test_create_object_failure():
    """Test that creating a DMObject with no path raises an Exception"""
    with pytest.raises(pamx.AMXError):
        pamx.DMObject()


def test_create_object_failure2():
    """Test that creating a DMObject with a non existent path raises an Exception"""
    with pytest.raises(pamx.AMXError):
        pamx.DMObject("Does.Not.Exist.")


def test_create_object_failure3():
    """Test that creating a DMObject with an incorrect object path raises an Exception"""
    with pytest.raises(pamx.AMXError):
        pamx.DMObject("Phonebook")


def test_create_object_failure4():
    """Test that creating a DMObject with an incorrect object path raises an Exception"""
    with pytest.raises(pamx.AMXError):
        pamx.DMObject("Phonebook.Contact")


def test_all_methods_have_async_equivalent():
    """Tests if DMObjects have a async equivalent"""
    conversion = pamx.DMObject("Conversion.")
    assert any(item in dir(conversion) for item in dir(conversion.async_methods))
    protected_async_methods = conversion.async_methods.protected
    assert any(item in dir(conversion.dmmngt) for item in dir(protected_async_methods))


def test_object_async_set_failure():
    """Test that a DMObject.async_methods cannot be set"""
    path = "Phonebook.Contact.OBJECTTEST."
    contact = pamx.DMObject(path)
    with pytest.raises(TypeError):
        contact.async_methods = 1


def test_object_async_call(connection):
    """ Perform add asynchronously."""
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.OBJECTASYNC")
    template = pamx.DMObject("Phonebook.Contact.")
    assert template.async_methods.protected.__dict__["add"]
    request = template.async_methods.protected.add({"name": "OBJECTASYNC"})
    request.wait()
    request.close()
    connection.get("Phonebook.Contact.OBJECTASYNC.")


def dm_async_handler(retval):
    """ ASYNC callback function"""
    assert retval[0]["object"] == "Phonebook.Contact.OBJECTASYNC2."


def test_dm_object_async_call_handler(connection):
    """ Perform add asynchronously with a function callback."""
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.OBJECTASYNC2")
    template = pamx.DMObject("Phonebook.Contact.")
    request = template.async_methods.protected.add({"name": "OBJECTASYNC2", "parameters": {
                                          "FirstName": "OBJECT", "LastName": "ASYNC"}},
                                          dm_async_handler)
    request.wait()
    connection.get("Phonebook.Contact.OBJECTASYNC2.")


def dm_async_handler_userdata(retval, userdata):
    """ ASYNC callback function with userdata"""
    assert retval[0]["object"] == userdata


def test_async_call_handler2(connection):
    """ Perform add asynchronously with a function callback and userdata."""
    with pytest.raises(pamx.AMXError):
        connection.get("Phonebook.Contact.OBJECTASYNC3")
    template = pamx.DMObject("Phonebook.Contact.")
    request = template.async_methods.protected.add(
        {"name": "OBJECTASYNC3"}, dm_async_handler_userdata, "Phonebook.Contact.OBJECTASYNC3.")
    request.wait()
    connection.get("Phonebook.Contact.OBJECTASYNC3.")


def test_async_call_error_in_handler():
    """ Perform add asynchronously with a callback function that raises an error."""
    template = pamx.DMObject("Phonebook.Contact.")
    request = template.async_methods.protected.add(
        {"name": "OBJECTASYNC4"}, dm_async_handler_userdata, "Phonebook.Contact.OBJECTASYNC3.")
    with pytest.raises(AssertionError):
        request.wait()


def test_async_call_wait_timeout():
    """
    Wait for asynchronous request that will timeout because
    the object that's being added already exists
    """
    template = pamx.DMObject("Phonebook.Contact.")
    request = template.async_methods.protected.add(
        {"name": "OBJECTASYNC4"}, dm_async_handler_userdata, "Phonebook.Contact.OBJECTASYNC4.")
    with pytest.raises(pamx.AMXError):
        request.wait()


def test_object_async_call_incorrect_parameters():
    """ Preforming an async call with userdata but no callback function shall raise an exception"""
    phonebook = pamx.DMObject("Phonebook.")
    with pytest.raises(pamx.AMXError):
        phonebook.async_methods.protected.get(userdata={"param": "value"})


def test_object_async_call_incorrect_parameters2():
    """ Preforming an async call with a non callable callback function shall raise an exception"""
    phonebook = pamx.DMObject("Phonebook.")
    with pytest.raises(TypeError):
        phonebook.async_methods.protected.get(callback="dm_async_handler")


def test_object_async_call_incorrect_parameters3():
    """
    Preforming an async call with parameters
    that aren't in a dictionary shall raise an exception
    """
    phonebook = pamx.DMObject("Phonebook.")
    with pytest.raises(pamx.AMXError):
        phonebook.async_methods.protected.get("test")


def test_async_protected_dir(connection):
    """ Test dir of DMObject.async_methods """
    phonebook = pamx.DMObject("Phonebook.")
    assert "get" in dir(phonebook.async_methods.protected)
    connection.access_level = "public"
    phonebook = pamx.DMObject("Phonebook.")
    assert "get" not in dir(phonebook.async_methods.protected)
    connection.access_level = "protected"


# pylint: disable=pointless-statement
def test_delete_object_function():
    """ Test DM object deletion """
    contact = pamx.DMObject("Phonebook.Contact.OBJECTTEST.")
    assert contact.FirstName == "OBJECT"
    assert contact.LastName == "TEST"
    contact.dmmngt.delete()
    with pytest.raises(pamx.AMXError):
        contact.FirstName
    with pytest.raises(pamx.AMXError):
        contact.LastName
