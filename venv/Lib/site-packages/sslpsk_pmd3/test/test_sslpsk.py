# Copyright 2017 David R. Bild
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

import os
import socket
import ssl
import sys
import threading
import unittest

import sslpsk_pmd3

HOST='localhost'
PORT=6000
TEST_DATA=b'abcdefghi'

class sslpsk3Test(unittest.TestCase):
    # ---------- setup/tear down functions
    def setUp(self):
        self.psk = b'c033f52671c61c8128f7f8a40be88038bcf2b07a6eb3095c36e3759f0cf40837'
        self.addr = (HOST, PORT)
        self.client_socket = socket.socket()
        self.server_socket = None
        self.accept_socket = socket.socket()
        self.client_psk_sock = None
        self.server_psk_sock = None

        self.startServer()
    
    def tearDown(self):
        for sock in [self.client_psk_sock or self.client_socket,
                     self.server_psk_sock or self.server_socket,
                     self.accept_socket]:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            finally:
                sock.close()

        self.client_socket = None
        self.server_socket = None
        self.accept_socket = None
        self.client_psk_sock = None
        self.server_psk_sock = None

    def startServer(self):
        self.accept_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.accept_socket.bind(self.addr)
        self.accept_socket.listen(1)

        def accept():
            self.server_socket, _ = self.accept_socket.accept()
        
            # wrap socket with TLS-PSK
            self.server_psk_sock = sslpsk_pmd3.wrap_socket(self.server_socket, psk=self.psk, ciphers='PSK-AES256-CBC-SHA',
                                                           ssl_version=ssl.PROTOCOL_TLSv1, server_side=True)
        
            # accept data from client
            data = self.server_psk_sock.recv(10)
            self.server_psk_sock.sendall(data.upper())

        threading.Thread(target = accept).start()

    def testClient(self):
        # initialize
        self.client_socket.connect(self.addr)
        
        # wrap socket with TLS-PSK
        self.client_psk_sock = sslpsk_pmd3.wrap_socket(self.client_socket, psk=self.psk, ciphers='PSK-AES256-CBC-SHA',
                                                       ssl_version=ssl.PROTOCOL_TLSv1, server_side=False)
        
        self.client_psk_sock.sendall(TEST_DATA)
        data = self.client_psk_sock.recv(10)
        print('data: %s' % data)
        self.assertTrue(data == TEST_DATA.upper(), 'Test Failed')

def main():
    unittest.main(buffer=False)

if __name__ == '__main__':
    main()
