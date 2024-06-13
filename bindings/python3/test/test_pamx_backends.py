#!/usr/bin/env pytest3
""" Testing python amx bindings object additions and deletions.
"""
import pytest
import pamx


def test_who_has(connection):
    """ Test whohas function"""
    assert pamx.bus.who_has("Phonebook.") == connection


def test_who_has_failure():
    """ Test whohas function with non existent path"""
    with pytest.raises(pamx.AMXError):
        pamx.bus.who_has("Does.Not.Exist.")


def test_who_has_incorrect_parameters():
    """ Test whohas function with wrong parameters"""
    with pytest.raises(pamx.AMXError):
        pamx.bus.who_has()


def test_load_backends():
    """ Load and removing backends"""
    assert "ubus" not in pamx.backend.list()
    pamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
    assert "ubus" in pamx.backend.list()
    pamx.backend.remove("ubus")
    assert "ubus" not in pamx.backend.list()


def test_set_backend_config():
    """Set a backend config"""
    pamx.backend.set_config()


def test_load_wrong_backend():
    """ Test if loading non existent backend raises error"""
    with pytest.raises(pamx.AMXError):
        pamx.backend.load("DoesNotExist")


def test_loading_backend_incorrect_parameters():
    """ Test if loading backend with incorrect parameters raises error"""
    with pytest.raises(pamx.AMXError):
        pamx.backend.load()


def test_remove_wrong_backend():
    """ Test if removing non existent backend raises error"""
    with pytest.raises(pamx.AMXError):
        pamx.backend.remove("DoesNotExist")


def test_remove_backend_incorrect_parameters():
    """ Test if removing backend with incorrect parameters raises error"""
    with pytest.raises(pamx.AMXError):
        pamx.backend.remove()


def test_loading_backend_incorrect_parameters2():
    """ Test if loading backend with incorrect parameters raises error"""
    with pytest.raises(pamx.AMXError):
        pamx.backend.load()


def test_remove_backend_incorrect_parameters3():
    """ Test if removing backend with incorrect parameters raises error"""
    with pytest.raises(pamx.AMXError):
        pamx.backend.remove()

# pylint: disable=pointless-statement


def test_connection_attributes(connection):
    """ Test connection object attributes"""
    assert connection.uri == "pcb:/tmp/local"
    with pytest.raises(TypeError):
        connection.uri = "Test"
    assert connection.access_level == "protected"
    desc = connection.describe("Phonebook.Contact.", functions=True)
    desc[0]["functions"]["_add"]
    connection.access_level = "public"
    assert connection.access_level == "public"
    desc = connection.describe("Phonebook.Contact.", functions=True)
    with pytest.raises(KeyError):
        desc[0]["functions"]["_add"]
    connection.access_level = "protected"
    with pytest.raises(TypeError):
        connection.access_level = "test"


def test_connect_incorrect_uri():
    """ Test if connecting to wrong uri raises error """
    with pytest.raises(pamx.AMXError):
        pamx.bus.connect("pcb:/does/not/exist")


def test_connect_incorrect_parameters():
    """ Test if connecting wrong parameters raises error """
    with pytest.raises(pamx.AMXError):
        pamx.bus.connect()
