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

"""
An echo client that sends secure messages to a server.
Entering a blank line will exit the client.
"""
import os
import time
import socket
import sys
from base64 import b64decode, b64encode
from aes_module import encrypt_aes
from digest_module import make_hash_sha512
import rsa_module
from cryptography.utils import int_from_bytes


def size_in_32bit(n):
    return '{0:032b}'.format(n)


def size_in_8bit(n):
    return '{0:08b}'.format(n)


def size_bin_int(n):
    return int(n, 2)


def prep_msg(aes_key, msg):
    # strip new line character from user input
    msg = msg.rstrip('\n')
    # find the hash of the aes_key
    h = make_hash_sha512(aes_key)
    # find the message length
    msg_len = size_in_32bit(len(msg))
    # assemble the message packet
    return h + msg_len + msg


def challenge_response(s, key_clie_pri, key_clie_pub, key_serv_pub):
    # implement a Challenge-Response Authentication protocol and derive a session key

    # Stage 1
    # Client Sends to server a magic number (serial) and the signature of magic number
    # encrypted with the servers public key

    seq_id = 1  # holds the sequence numbers in packet's

    serial = int_from_bytes(os.urandom(4), byteorder="big")
    m = size_in_8bit(seq_id) + size_in_32bit(serial)
    serial_sig = rsa_module.sign_data(m, key_clie_pri)
    message1 = serial_sig + m
    ciphertext1 = rsa_module.rsa_cbc_encrypt(message1, key_serv_pub)
    s.sendall(ciphertext1)

    # time delay if under attack
    time.sleep(1)

    # Stage 2
    # Recieve Data
    ciphertext2 = s.recv(size)
    # Decrypt Data
    message2 = rsa_module.rsa_cbc_dencrypt(ciphertext2, key_clie_pri)
    # Verify Data
    serial_sig_server = message2[:256]
    rsa_module.verify_data(message2[256:], serial_sig_server, key_serv_pub)
    # Extract Data
    seq_id_server = message2[256:256 + 8]
    serial_reply = message2[256 + 8:256 + 8 + 32]
    serial_server = message2[256 + 8 + 32:256 + 8 + 32 + 32]

    if serial_reply != size_in_32bit(serial):
        print "Signature don't match"
        return False
    print "Server is authenticated"

    # update sequence id
    seq_id = seq_id + size_bin_int(seq_id_server)

    m = size_in_8bit(seq_id) + serial_server
    serial_sig = rsa_module.sign_data(m, key_clie_pri)
    message3 = serial_sig + m
    ciphertext3 = rsa_module.rsa_cbc_encrypt(message3, key_serv_pub)
    s.sendall(ciphertext3)
    time.sleep(1)

    print "Challenge Response was Successful"
    # Stage 4 get AES key from server (Session Key)
    session_key = s.recv(size)
    session_key = b64decode(session_key)

    aes_data = rsa_module.rsa_cbc_dencrypt(session_key, key_clie_pri)
    aes_sig = aes_data[:256]
    aes_key = aes_data[256:]

    rsa_module.verify_data(aes_key, aes_sig, key_serv_pub)
    return aes_key


# server info
host = 'localhost'
port = 50000
size = 4096  # max packet size

print "Trying to connect to server %s:%d ->" % (host, port),
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print "Ok"

print "Load rsa keys...",
key_serv_pub = rsa_module.load_pub_key_rsa("rsa_keys/server_pub.pem")
key_clie_pri = rsa_module.load_priv_key_rsa("rsa_keys/client_pri.pem")
key_clie_pub = rsa_module.load_pub_key_rsa("rsa_keys/client_pub.pem")
print "Ok"

running = 1

print "Challenge Response with server in progress...",

aes_key = challenge_response(s, key_clie_pri, key_clie_pub, key_serv_pub)

if aes_key == False:
    s.close()
    running = 0
    print "Server responce is wrong"
    print "Disconnecting now"

print "\nAES key is %s\n" % b64encode(aes_key)

while running:
    # read from keyboard
    print "Enter a message to send (Press enter to quit) # ",
    line = sys.stdin.readline()
    if line == '\n':
        running = 0
        message = prep_msg(aes_key, "secure-close")
        cipher_aes = encrypt_aes(aes_key, message)
        s.send(cipher_aes)
        time.sleep(1)
        print "Client bye bye"
        break
    print "Sending message to server"
    message = prep_msg(aes_key, line)
    cipher_aes = encrypt_aes(aes_key, message)
    s.send(cipher_aes)
s.close()
