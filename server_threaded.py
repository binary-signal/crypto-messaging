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
An echo server that uses threads to handle multiple clients at a time.
Entering any line of input at the terminal will exit the server.
"""
import time
import os
import select
import socket
import sys
import threading
from base64 import b64encode
import rsa_module
from Crypto import Random
import aes_module
from digest_module import make_hash_sha512
from rsa_module import load_pub_key_rsa, load_priv_key_rsa
from cryptography.utils import int_from_bytes


class Server:
    def __init__(self):
        self.host = ''
        self.port = 50000
        self.backlog = 5
        self.size = 4096
        self.server = None
        self.threads = []
        print "loading rsa keys...",
        self.public_key = load_pub_key_rsa("rsa_keys/server_pub.pem")
        self.private_key = load_priv_key_rsa("rsa_keys/server_pri.pem")
        print "ok"

    def open_socket(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.host, self.port))
            self.server.listen(5)
        except socket.error, (value, message):
            if self.server:
                self.server.close()
            print "Could not open socket: " + message
            sys.exit(1)

    def run(self):
        print "Server start up...",
        self.open_socket()
        print "ok"
        input = [self.server, sys.stdin]
        running = 1
        print("Server is up and running on port "), self.port
        print("\nWaiting for a connection...\n")
        while running:
            inputready, outputready, exceptready = select.select(input, [], [])

            for s in inputready:

                if s == self.server:
                    # handle the server socket
                    c = Client(self.server.accept())
                    c.start()
                    self.threads.append(c)

                elif s == sys.stdin:
                    # handle standard input
                    junk = sys.stdin.readline()
                    running = 0

        # close all threads

        self.server.close()
        for c in self.threads:
            c.join()


class Client(threading.Thread):
    def __init__(self, (client, address)):
        threading.Thread.__init__(self)
        self.client = client
        self.address = address
        self.size = 4096
        self.client_public_key = load_pub_key_rsa("rsa_keys/client_pub.pem")
        self.server_private_key = load_priv_key_rsa("rsa_keys/server_pri.pem")


    def size_in_32bit(self, n):
        return '{0:032b}'.format(n)

    def size_in_8bit(self, n):
        return '{0:08b}'.format(n)

    def size_bin_int(self, n):
        return int(n, 2)

    def parse_message(self, plain_text):
        h = plain_text[0:128]
        # print "message hash %s" % h
        n = plain_text[128:128 + 32]
        # print "binary length %d" % len(n)
        msg_len = self.size_bin_int(n)
        # print "message len %d" % msg_len
        text = plain_text[128 + 32:]
        # print "message: %s " % text
        return text, h, msg_len

    def message_checksum(self, message, msg_hash):
        h = make_hash_sha512(message)
        if h == msg_hash:
            return True

    def log(self, id, message=[]):
        with open("connection.log", 'ab') as logfile:
            logfile.write("-- msg --\n")
            logfile.write("client: " + str(self.address) + "\n")
            logfile.write("msg_id: " + str(id) + "\n")
            logfile.write("message: " + message[0] + "\n")
            logfile.write("msg_len: " + str(message[1]) + "\n")
            logfile.write("sha512: " + message[2] + "\n")
            logfile.write("-- end --\n")

    def run(self):
        print "Client Handler tid: %s" % self.getName()
        running = 1

        msg_id = 0
        seq_id = 1
        print "Challenge Responce in progress...",
        # Stage 1:: Receive Client Magic Number
        ciphertext1 = self.client.recv(self.size)
        # Decrypt Challenge
        message1 = rsa_module.rsa_cbc_dencrypt(ciphertext1, self.server_private_key)
        # Verify Destination and authenticity
        serial_client_sig = message1[:256]
        rsa_module.verify_data(message1[256:], serial_client_sig, self.client_public_key)

        # Extract Data
        seq_id_client = message1[256:256 + 8]
        serial_client = message1[256 + 8:]

        # Stage 2:: Send server magic number and client magic number back to client encrypted and signed
        serial = int_from_bytes(os.urandom(4), byteorder="big")

        # update sequecne id number
        seq_id = seq_id + self.size_bin_int(seq_id_client)
        data = self.size_in_8bit(seq_id) + serial_client + self.size_in_32bit(serial)
        sig2 = rsa_module.sign_data(data, self.server_private_key)
        message2 = sig2 + data
        ciphertext2 = rsa_module.rsa_cbc_encrypt(message2, self.client_public_key)
        self.client.send(ciphertext2)
        time.sleep(1)

        # Stage 3
        ciphertext3 = self.client.recv(self.size)
        message3 = rsa_module.rsa_cbc_dencrypt(ciphertext3, self.server_private_key)
        sig3 = message3[:256]
        rsa_module.verify_data(message3[256:], sig3, self.client_public_key)

        # Finale stage Session Key
        # upadte sequence id
        seq_id = seq_id + self.size_bin_int(message3[256:256 + 8])
        serial_client_reply = message3[256 + 8:256 + 8 + 32]
        if serial_client_reply == self.size_in_32bit(serial):
            print "User Authenticated!"
            print "Challenge Response was Successful\n"
            print "Sending Session Key...",
            key_aes = Random.get_random_bytes(32)
            key_aes_sig = rsa_module.sign_data(key_aes, self.server_private_key)
            key = key_aes_sig + key_aes
            key_aes_encrypted = rsa_module.rsa_cbc_encrypt(key, self.client_public_key)
            self.client.send(b64encode(key_aes_encrypted))
            print "ok"
        else:
            print "Can't authenticate user or man in the middle attack"
            print "Terminating Connection now"
            self.client.close()
            running = 0

        while running:
            aes_cipher_text = self.client.recv(self.size)

            #if aes_cipher_text == "":
            #    continue

            plain_text = aes_module.decrypt_aes(key_aes, aes_cipher_text)

            text, msg_hash, msg_len = self.parse_message(plain_text)
            msg_id += 1

            self.log(msg_id, [text, msg_len, msg_hash])
            print "\n*Received from: ",
            print self.address
            print "\tMessage: %s" % text
            if self.message_checksum(key_aes, msg_hash):
                print "\tHash check ok"
            else:
                print "\tHash values don't match damaged message! "
            if text == "secure-close":
                print "\tClient disconected"
                self.client.close()
                running = 0


if __name__ == "__main__":
    s = Server()
    s.run()
