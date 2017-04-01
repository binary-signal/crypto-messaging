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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from binascii import hexlify
from Crypto.Util import strxor
import random

RSA_BLOCK_SIZE = 128


def pad(s):
    return s + (RSA_BLOCK_SIZE - len(s) % RSA_BLOCK_SIZE) * chr(RSA_BLOCK_SIZE - len(s) % RSA_BLOCK_SIZE)


def unpad(s):
    return s[0:-ord(s[-1])]


def msg_db(m, desc, mode):
    # print debugging messages
    print "$ %s -> length %d" % (desc, len(m))
    print "\t****"
    if mode == "hex":
        print("\t: %s" % hexlify(m))
    else:
        print("\t: %s" % m)
    print "\t****\n"


def rsa_key(bits=2048):
    # generate rsa key default size 2048 bit
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
    )
    return private_key


def load_priv_key_rsa(keypath):
    # load rsa key from file in pem format
    with open(keypath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
        )

        return private_key


def load_pub_key_rsa(keypath):
    # load rsa key from file in pem format
    with open(keypath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
        )

        return public_key


def serialize_private_key(private_key):
    # serialize a private key before saving to file
    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
    )

    return pem


def serialize_public_key(private_key):
    # serialize a public key before saving to file
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem


def save_to_file(data, file):
    # save some data to some file
    with open(file, "wb") as f:
        f.write(data)
        f.close()


def sign_data(message, private_key):
    # sign data with a private key
    signer = private_key.signer(
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),  # change to sha 512 in the future
                    salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )
    # message = b"A message I want to sign"
    signer.update(message)
    signature = signer.finalize()

    return signature


def public_key(private_key):
    # return the public key from a private key
    return private_key.public_key()


def verify_data(message, signature, public_key):
    verifier = public_key.verifier(
            signature,
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )
    verifier.update(message)

    verifier.verify()


def rsa_encrypt(message, public_key):
    # ecnrypt a message with rsa oaep padding
    ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
            )
    )

    return ciphertext


# dectrypt encrypted message (aka ciphertext)
def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(ciphertext,
                                    padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                            algorithm=hashes.SHA1(),
                                            label=None
                                    )
                                    )
    return plaintext


def rsa_cbc_encrypt(data, key):
    # apply rsa encryption with cipber block chaining
    # before enryption pad data to rsa block size  128 bits
    data_padded = pad(data)

    # split input data in chuncks of block size
    c = []
    for i in xrange(0, len(data_padded), RSA_BLOCK_SIZE):
        x = data_padded[i:i + RSA_BLOCK_SIZE]
        c.append(x)

    ciphers_list = []

    # prepair IV vector for the first encryption round
    # Random.get_random_bytes(128)
    IV = ''.join(chr(random.randint(0, 0xFF)) for i in range(128))
    IV2 = IV

    # encrypt each chunk with rsa
    for d in c:
        # xor data with iv
        dx = strxor.strxor(d, IV)
        # encrypt xored data
        cipher_text = rsa_encrypt(dx, key)

        # update iv from cipher text
        IV = cipher_text[0:128]
        ciphers_list.append(cipher_text)
    # last block save initial IV for decryption
    ciphers_list.append(IV2)

    return "".join(ciphers_list)


def rsa_cbc_dencrypt(data, key):
    # extract iv from encrypted data
    IV = data[-128:]
    cipher_text = data[:-128]

    # split cipher text in chunks  of 2*RSA Block size
    c = []
    for i in xrange(0, len(cipher_text), 2 * RSA_BLOCK_SIZE):
        x = cipher_text[i:i + 2 * RSA_BLOCK_SIZE]
        c.append(x)

    # decrypt each chunk
    text = []
    for d in c:
        dx = rsa_decrypt(d, key)
        # clear_text=sxor(dx, IV)

        clear_text = strxor.strxor(dx, IV)
        IV = d[0:128]
        text.append(clear_text)

    big_data = "".join(text)
    r = unpad(big_data)
    return r


# generate keys
# server
#key_server = rsa_key(2048)

#pem__private_server = serialize_private_key(key_server)
#pem_public_server = serialize_public_key(key_server)

#save_to_file(pem__private_server, "server_pri.pem")
#save_to_file(pem_public_server, "server_pub.pem")

# client
#key_client = rsa_key(2048)
#pem__private_client = serialize_private_key(key_client)
#pem_public_client = serialize_public_key(key_client)

#save_to_file(pem__private_client, "client_pri.pem")
#save_to_file(pem_public_client, "client_pub.pem")
