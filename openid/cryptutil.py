"""Module containing a cryptographic-quality source of randomness and
other cryptographically useful functionality

Other configurations will need a quality source of random bytes and
access to a function that will convert binary strings to long
integers.
"""
from __future__ import unicode_literals

import codecs
import hashlib
import hmac
import warnings

import six

from openid.oidutil import fromBase64, string_to_text, toBase64

__all__ = [
    'base64ToLong',
    'binaryToLong',
    'hmacSha1',
    'hmacSha256',
    'longToBase64',
    'longToBinary',
    'int_to_bytes',
    'bytes_to_int',
]


class HashContainer(object):
    def __init__(self, hash_constructor):
        self.new = hash_constructor
        self.digest_size = hash_constructor().digest_size


sha1_module = HashContainer(hashlib.sha1)
sha256_module = HashContainer(hashlib.sha256)


def hmacSha1(key, text):
    """
    Return a SHA1 HMAC.

    @type key: six.binary_type
    @type text: six.text_type, six.binary_type is deprecated
    @rtype: six.binary_type
    """
    text = string_to_text(text, "Binary values for text are deprecated. Use text input instead.")
    return hmac.new(key, text.encode('utf-8'), sha1_module).digest()


def hmacSha256(key, text):
    """
    Return a SHA256 HMAC.

    @type key: six.binary_type
    @type text: six.text_type, six.binary_type is deprecated
    @rtype: six.binary_type
    """
    text = string_to_text(text, "Binary values for text are deprecated. Use text input instead.")
    return hmac.new(key, text.encode('utf-8'), sha256_module).digest()


def bytes_to_int(value):
    """
    Convert byte string to integer.

    @type value: six.binary_type
    @rtype: Union[six.integer_types]
    """
    return int(codecs.encode(value, 'hex'), 16)


def int_to_bytes(value):
    """
    Convert integer to byte string.

    @type value: Union[six.integer_types]
    @rtype: six.binary_type
    """
    hex_value = '{:x}'.format(value)
    if len(hex_value) % 2:
        hex_value = '0' + hex_value
    array = bytearray.fromhex(hex_value)
    # First bit must be zero. If it isn't, the bytes must be prepended by zero byte.
    # See http://openid.net/specs/openid-authentication-2_0.html#btwoc for details.
    if array[0] > 127:
        array = bytearray([0]) + array
    return six.binary_type(array)


# Deprecated versions of bytes <--> int conversions
def longToBinary(value):
    warnings.warn("Function longToBinary is deprecated in favor of int_to_bytes.", DeprecationWarning)
    return int_to_bytes(value)


def binaryToLong(s):
    warnings.warn("Function binaryToLong is deprecated in favor of bytes_to_int.", DeprecationWarning)
    return bytes_to_int(s)


def longToBase64(l):
    return toBase64(int_to_bytes(l))


def base64ToLong(s):
    return bytes_to_int(fromBase64(s))
