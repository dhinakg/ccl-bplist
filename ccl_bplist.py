"""
Copyright (c) 2012-2016, CCL Forensics
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the CCL Forensics nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CCL FORENSICS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import datetime
import plistlib

__version__ = "0.21"
__description__ = "Converts Apple binary PList files into a native Python data structure"
__contact__ = "Alex Caithness"


def convert_NSMutableDictionary(obj, uid_decode):
    """Converts a NSKeyedArchiver serialised NSMutableDictionary into
       a straight dictionary (rather than two lists as it is serialised
       as)"""

    # The dictionary is serialised as two lists (one for keys and one
    # for values) which obviously removes all convenience afforded by
    # dictionaries. This function converts this structure to an
    # actual dictionary so that values can be accessed by key.

    if not is_nsmutabledictionary(obj, uid_decode):
        raise ValueError("obj does not have the correct structure for a NSDictionary/NSMutableDictionary serialised to a NSKeyedArchiver")
    keys = obj["NS.keys"]
    vals = obj["NS.objects"]

    # sense check the keys and values:
    if not isinstance(keys, list):
        raise TypeError("The 'NS.keys' value is an unexpected type (expected list; actual: {0}".format(type(keys)))
    if not isinstance(vals, list):
        raise TypeError("The 'NS.objects' value is an unexpected type (expected list; actual: {0}".format(type(vals)))
    if len(keys) != len(vals):
        raise ValueError("The length of the 'NS.keys' list ({0}) is not equal to that of the 'NS.objects ({1})".format(len(keys), len(vals)))

    result = {}
    for i, k in enumerate(keys):
        if k in result:
            raise ValueError("The 'NS.keys' list contains duplicate entries")
        result[k] = vals[i]

    return result


def convert_NSArray(obj, uid_decode):
    if not is_nsarray(obj, uid_decode):
        raise ValueError("obj does not have the correct structure for a NSArray/NSMutableArray serialised to a NSKeyedArchiver")

    return obj["NS.objects"]

# NSSet convenience functions


def convert_NSSet(obj, uid_decode):
    if not is_isnsset(obj, uid_decode):
        raise ValueError("obj does not have the correct structure for a NSSet/NSMutableSet serialised to a NSKeyedArchiver")

    return list(obj["NS.objects"])


def convert_NSString(obj, uid_decode):
    if not is_nsstring(obj, uid_decode):
        raise ValueError("obj does not have the correct structure for a NSString/NSMutableString serialised to a NSKeyedArchiver")

    return obj["NS.string"]


def convert_NSDate(obj, uid_decode):
    if not is_nsdate(obj, uid_decode):
        raise ValueError("obj does not have the correct structure for a NSDate serialised to a NSKeyedArchiver")

    return datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=obj["NS.time"])


def is_type(obj, uid_decode, required_keys, class_names):
    if isinstance(required_keys, str):
        required_keys = [required_keys]
    if not (isinstance(obj, dict) and all([key in obj for key in required_keys])):
        return False
    class_name = uid_decode(obj.get("$class", {})).get("$classname")
    return class_name in class_names


# NSMutableDictionary convenience functions
def is_nsmutabledictionary(obj, uid_decode):
    return is_type(obj, uid_decode, ("NS.objects", "NS.keys"), ("NSMutableDictionary", "NSDictionary"))


# NSArray convenience functions
def is_nsarray(obj, uid_decode):
    return is_type(obj, uid_decode, ("NS.objects"), ("NSArray", "NSMutableArray"))


# NSSet convenience functions


def is_isnsset(obj, uid_decode):
    return is_type(obj, uid_decode, ("NS.objects"), ("NSSet", "NSMutableSet"))


# NSString convenience functions
def is_nsstring(obj, uid_decode):
    return is_type(obj, uid_decode, ("NS.string"), ("NSString", "NSMutableString"))


# NSDate convenience functions
def is_nsdate(obj, uid_decode):
    return is_type(obj, uid_decode, ("NS.time"), ("NSDate"))

# NSDate convenience functions
def is_null(obj, uid_decode):
    return isinstance(obj, plistlib.UID) and uid_decode(obj) == "$null"



    
def convert_null(obj, uid_decode):
    if not is_null(obj, uid_decode):
        raise ValueError("obj does not have the correct structure for a NSString/NSMutableString serialised to a NSKeyedArchiver")

    return None