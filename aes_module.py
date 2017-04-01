#!/usr/bin/env python
# Author: Euaggelos Mouroutsos

# Secure Communication Project
# Implementation of a cryptographic utility

# Copyright (c) 2015, Euaggelos Mouroutsos
# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met: 1. Redistributions
# of source code must retain the above copyright notice, this list of conditions and
#  the following disclaimer. 2. Redistributions in binary form must reproduce the
# above copyright notice, this list of conditions and the following disclaimer in
# the documentation and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

from Crypto import Random
from Crypto.Cipher import AES

# generatate an aes key of n bits
def make_aes_key(bits=256):
    size = bits/8
    key = Random.get_random_bytes(size)
    return key

def dump_aes_key(key, key_file='aes.key'):
    # output file is hardcoded, the key file will be overwritten
    # in the next program execution with a new key generated randomly

    with open(key_file, 'wb') as outfile:
        outfile.write(key)

# apply pkcs5 padding scheme in input
def pkcs5_pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

# reverse pkcs5 padding
def pkcs5_unpad(s):
    return s[0:-ord(s[-1])]


def encrypt_aes(key, message):
    msg_len = len(message)
    if msg_len % AES.block_size != 0:
        message = pkcs5_pad(message)
        #print 'padded msg -> ' + message
        #print 'new len %d' % len(message)

    # make an AES object with key,mode ecb
    aes_obj = AES.new(key, AES.MODE_ECB)

    # encrypt babe!
    cipher_text = aes_obj.encrypt(message)

    return cipher_text


# decrypt encrypted file to plain text files blah blah....
def decrypt_aes(key, encrypted_data):
    # make an aes object for the decryption
    aes_obj = AES.new(key, AES.MODE_ECB)  # decrypt  the cipher text as if there is no tomorrow
    plain_text = aes_obj.decrypt(encrypted_data)

    # before returning the plaintext remove any padding applied
    return pkcs5_unpad(plain_text)
