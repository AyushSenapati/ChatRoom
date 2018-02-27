#! /usr/bin/env python3

import base64
from Crypto.Cipher import AES
import hashlib


def hasher(key):
    #hash_object = hashlib.sha512(key)
    #hexd = hash_object.hexdigest()
    hash_object = hashlib.md5(key)
    hex_dig = hash_object.hexdigest()
    return hex_dig

def encrypt(secret, data):
    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s : s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    cipher = AES.new(secret)
    encoded = EncodeAES(cipher, data)
    return encoded

def decrypt(secret, data):
    BLOCK_SIZE = 32
    PADDING = '{'
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).decode().rstrip(PADDING)
    cipher = AES.new(secret)
    decoded = DecodeAES(cipher, data)
    return decoded
