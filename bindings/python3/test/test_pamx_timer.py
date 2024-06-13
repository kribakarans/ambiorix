#!/usr/bin/env pytest3
""" Testing python pamx bindings timers.
"""
import pytest
import pamx

COUNTER = 0


def end_of_timer():
    """Callback function for end of timer."""
    pamx.eventloop.stop()


def end_of_timer_userdata(value):
    """Callback function for end of timer with userdata."""
    assert value == 100, "Wrong value."
    pamx.eventloop.stop()


class HandlerException(Exception):
    """Raised when a callback functions raises an exception"""


def exception_callback():
    """Callback function that raises an exception"""
    raise HandlerException("Timer callback exception")


# pylint: disable=global-statement
def increment():
    """
    Increment the global COUNTER value.
    Stop at value to indicate that the timer interval at least triggered this callback twice
    """
    global COUNTER
    COUNTER = COUNTER + 1
    if COUNTER == 2:
        pamx.eventloop.stop()


def test_timer():
    """Test pamx timer functionality."""
    timer = pamx.Timer(end_of_timer)
    assert timer.state == "OFF", "Timer is not off"
    assert timer.interval == 0, "there is an interval."
    timer.start(1000)
    assert timer.remaining == 1000, "Incorrect amount of time left."
    assert timer.state == "RUNNING", "Timer is not off"
    timer.stop()
    assert timer.state == "OFF", "Timer has not stopped."
    assert timer.remaining == 0, "Incorrect amount of time left."
    timer.start(1000)
    assert timer.remaining == 1000, "Incorrect amount of time left."
    assert timer.state == "RUNNING", "Timer is not off"
    pamx.eventloop.start()
    assert timer.interval == 0, "there is an interval."


def test_timer_callback_userdata():
    """Test pamx timer with callback and userdate."""
    timer = pamx.Timer(end_of_timer_userdata, 100)
    assert timer.state == "OFF", "Timer is not off"
    assert timer.interval == 0, "there is an interval."
    timer.start(1000)
    pamx.eventloop.start()


def test_timer_interval():
    """
    Test pamx timer interval functionality.
    Makes sure it triggers the callback multiple times.
    """
    global COUNTER
    COUNTER = 0
    timer = pamx.Timer(callback=increment, interval=1000)
    assert timer.state == "OFF", "Timer is not off"
    assert timer.interval == 1000, "there is an interval."
    timer.start(1000)
    pamx.eventloop.start()
    assert COUNTER == 2, "Interval doesn't work."


def test_timer_handler_exception():
    """Test pamx timer with a callback that raises an exception."""
    timer = pamx.Timer(callback=exception_callback, interval=1000)
    timer.start(1000)
    with pytest.raises(HandlerException):
        pamx.eventloop.start()


def test_timer_set_interval():
    """Test setting pamx timer interval."""
    global COUNTER
    COUNTER = 0
    timer = pamx.Timer(callback=increment)
    timer.interval = 1000
    assert timer.state == "OFF", "Timer is not off"
    assert timer.interval == 1000, "there is an interval."
    timer.start(1000)
    pamx.eventloop.start()
    assert COUNTER == 2, "Interval doesn't work."


def test_timer_set_remaining():
    """Test if manually setting a pamx timer's remaining value \
    raises an error."""
    timer = pamx.Timer(callback=increment)
    with pytest.raises(TypeError):
        timer.remaining = 0


def test_timer_illegal_interval():
    """Test if creating a timer with a interval value raises an error."""
    with pytest.raises(pamx.AMXError):
        pamx.Timer(end_of_timer, interval="1")


def test_timer_no_callback():
    """Test if creating a timer with no callback raises an error."""
    with pytest.raises(pamx.AMXError):
        pamx.Timer()


def test_timer_illegal_callback():
    """Test if creating a timer with a not callable callback raises an error."""
    with pytest.raises(pamx.AMXError):
        pamx.Timer(callback="function")


def test_timer_illegal_start():
    """
    Test if starting an timer without
    specifying an end time raises an error.
    """
    timer = pamx.Timer(callback=increment)
    with pytest.raises(pamx.AMXError):
        timer.start()


def test_timer_illegal_set_interval():
    """Test if setting an illegal interval for a pamx timer raises an error."""
    with pytest.raises(TypeError):
        timer = pamx.Timer(callback=increment)
        timer.interval = "1"


def test_timer_illegal_set_state():
    """Test if manually setting an illegal state \
    for a pamx timer raises an error."""
    with pytest.raises(AttributeError):
        global COUNTER
        COUNTER = 0
        timer = pamx.Timer(callback=increment)
        timer.state = "EXPIRED"
