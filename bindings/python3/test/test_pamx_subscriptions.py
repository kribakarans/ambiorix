#!/usr/bin/env pytest3
""" Testing python amx bindings subscriptions.
"""
import pytest
import pamx


def contact_added(sig_name, data):
    """ Callback function for subscriptions without userdata """
    assert sig_name == 'Phonebook.Contact'
    assert data['notification'] == 'dm:instance-added'
    assert data['object'] == 'Phonebook.Contact.'
    assert data['name'] == 'SubTest'
    assert data['parameters'] == {
        "FirstName": "Subscription",
        "LastName": "Test",
        "Plugin": "PAMX"}
    pamx.eventloop.stop()


def contact_added_with_userdata(sig_name, data, userdata):
    """ Callback function for subscriptions with userdata """
    assert sig_name == 'Phonebook.Contact'
    assert data['notification'] == 'dm:instance-added'
    assert data['object'] == 'Phonebook.Contact.'
    assert data['name'] == userdata[0]
    assert data['parameters'] == userdata[1]
    pamx.eventloop.stop()


def test_add_instance_subscription(connection):
    """Test subscribe to instance additions"""
    sub = connection.subscribe(
        "Phonebook.Contact.",
        "notification in ['dm:instance-added']",
        contact_added)
    connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "SubTest", "parameters": {
                "FirstName": "Subscription", "LastName": "Test"}})
    pamx.eventloop.start()
    sub.close()


def test_add_instance_subscription_with_userdata(connection):
    """
    Test to see if subscribing on dm:instance-added events is possible
    and to make sure the callback function gets the user data.
    """
    params = {
        "FirstName": "Subscription",
        "LastName": "Test2",
        "Plugin": "PAMX"}
    sub = connection.subscribe(
        "Phonebook.Contact.",
        "notification in ['dm:instance-added']",
        contact_added_with_userdata,
        ["SubTest2", params])
    connection.async_call(
        "Phonebook.Contact.", "_add", {
            "name": "SubTest2", "parameters": params})
    pamx.eventloop.start()
    sub.close()


def test_sub_incorrect_parameters(connection):
    """ Perform subscribe with no parameters which will raise an error."""
    with pytest.raises(pamx.AMXError):
        connection.subscribe()


def test_sub_incorrect_parameters2(connection):
    """ Perform subscribe with a non callable callback function value which will raise an error."""
    with pytest.raises(TypeError):
        connection.subscribe(
            "Phonebook.Contact.",
            "notification in ['dm:instance-added']",
            "cb_function")


class HandlerException(Exception):
    """Raised when a callback functions raises an exception"""


def error_callback(sig_name, data):
    """ Callback function which will raise an exception"""
    raise HandlerException("Subscription callback exception")


def test_sub_failure(connection):
    """ Perform subscribe with callback function which will raise an error."""
    params = {"FirstName": "Subscription", "LastName": "Test4"}
    connection.subscribe(
        "Phonebook.Contact.",
        "notification in ['dm:instance-added']",
        error_callback)
    with pytest.raises(HandlerException):
        connection.async_call(
            "Phonebook.Contact.", "_add", {
                "name": "SubTest3", "parameters": params})
        pamx.eventloop.start()
