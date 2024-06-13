#!/usr/bin/env pytest3
""" Testing python amx bindings value conversions.
"""
from datetime import datetime
import pamx


def test_conversion(connection):
    """ Test variant to python conversion"""
    params = {"SSV": "one two three",
              "Double": '8.000000e+00',
              "Int64": 64,
              "Int8": 8,
              "CSV": "one,two,three",
              "Bool": True,
              "FalseBool": False,
              "Int32": 32,
              "UInt8": 8,
              "Int16": 16,
              "UInt64": 64,
              "String": "String",
              "UInt32": 32,
              "UInt16": 16,
              "Timestamp": "0001-01-01T00:00:00Z"
              }
    conversion = connection.get("Conversion.")
    conversion_obj = pamx.DMObject("Conversion.")
    assert conversion_obj.__dict__["Int64"] == 64
    assert conversion[0]["Conversion."] == params


def test_conversion2(connection):
    """ Test python to variant conversion"""
    params = {"SSV": "four five six",
              "Double": 8.5,
              "Int64": -164,
              "Int8": -18,
              "CSV": "four,five,six",
              "Bool": False,
              "FalseBool": True,
              "Int32": -132,
              "UInt8": 18,
              "Int16": -116,
              "UInt64": 164,
              "String": "String2",
              "UInt32": 132,
              "UInt16": 116,
              "Timestamp": "0002-01-01T00:00:00Z"
              }
    connection.set("Conversion.", params)
    params["Double"] = '8.500000e+00'
    conversion = connection.get("Conversion.")
    assert conversion[0]["Conversion."] == params


def test_timestamp_conversion(connection):
    """ Test timestamp python to variant conversion"""
    timestamp = connection.call("Conversion.", "get_timestamp")
    assert timestamp[0] != "2021-01-01T00:00:00Z"
    datetime_obj = datetime(year=2021, month=1, day=1)
    connection.call(
        "Conversion.", "set_timestamp", {
            "timestamp": datetime_obj})
    timestamp = connection.call("Conversion.", "get_timestamp")
    assert timestamp[0] == "2021-01-01T00:00:00Z"
