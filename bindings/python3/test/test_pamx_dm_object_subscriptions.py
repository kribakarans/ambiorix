#!/usr/bin/env pytest3
""" Testing python amx bindings subscriptions via DMObject.
"""
import pytest
import pamx


def dm_contact_added(sig_name, data):
    """ Callback function for subscriptions without userdata """
    assert sig_name == 'Phonebook.Contact'
    assert data['notification'] == 'dm:instance-added'
    assert data['object'] == 'Phonebook.Contact.'
    assert data['name'] == 'DMSubTest'
    assert data['parameters'] == {
        "FirstName": "Subscription",
        "LastName": "Test",
        "Plugin": "PAMX"}
    pamx.eventloop.stop()


def dm_contact_added_with_userdata(sig_name, data, userdata):
    """ Callback function for subscriptions with userdata """
    assert sig_name == 'Phonebook.Contact'
    assert data['notification'] == 'dm:instance-added'
    assert data['object'] == 'Phonebook.Contact.'
    assert data['name'] == 'DMSubTest2'
    assert data['parameters'] == userdata
    pamx.eventloop.stop()


def test_dm_add_instance_subscription(connection):
    """Test subsrcibing to instance addition."""
    template = pamx.DMObject("Phonebook.Contact.")
    sub = template.dmmngt.subscribe(
        "notification in ['dm:instance-added']",
        dm_contact_added)
    connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "DMSubTest", "parameters": {
                "FirstName": "Subscription", "LastName": "Test"}})
    pamx.eventloop.start()
    sub.close()


def test_dm_add_instance_subscription_with_userdata(connection):
    """Test subsrcibing to instance addition with a callback function with userdata."""
    template = pamx.DMObject("Phonebook.Contact.")
    userdata = {
        "FirstName": "Subscription",
        "LastName": "Test",
        "Plugin": "PAMX"}
    sub = template.dmmngt.subscribe(
        "notification in ['dm:instance-added']",
        dm_contact_added_with_userdata,
        userdata)
    connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "DMSubTest2", "parameters": userdata})
    pamx.eventloop.start()
    sub.close()


def test_dm_sub_incorrect_parameters():
    """ Perform subscribe with no parameters which will raise an error."""
    template = pamx.DMObject("Phonebook.Contact.")
    with pytest.raises(pamx.AMXError):
        template.dmmngt.subscribe()


def test_dm_sub_incorrect_parameters2():
    """
    Perform subscribe with incorrect parameters (non string expression)
    which will raise an error.
    """
    template = pamx.DMObject("Phonebook.Contact.")
    with pytest.raises(pamx.AMXError):
        template.dmmngt.subscribe(1, dm_contact_added)


def test_dm_sub_incorrect_parameters3():
    """
    Perform subscribe with incorrect parameters (non callable callback function)
    which will raise an error.
    """
    template = pamx.DMObject("Phonebook.Contact.")
    with pytest.raises(TypeError):
        template.dmmngt.subscribe(
            "notification in ['dm:instance-added']",
            "dm_contact_added")
