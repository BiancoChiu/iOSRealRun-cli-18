from __future__ import print_function

import socket
import ssl

import sslpsk_pmd3

PSKS = {'server1' : b'abcdef',
        'server2' : b'uvwxyz'}

def client(host, port, psk):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((host, port))

    ssl_sock = sslpsk_pmd3.wrap_socket(tcp_socket,
                                       ssl_version=ssl.PROTOCOL_TLSv1,
                                       ciphers='ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH',
                                       psk=lambda hint: (PSKS[hint], b'client1'))

    msg = "ping"
    ssl_sock.sendall(msg.encode())
    msg = ssl_sock.recv(4).decode()
    print('Client received: %s'%(msg))

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()

def main():
    host = '127.0.0.1'
    port = 6000
    client(host, port, PSKS)

if __name__ == '__main__':
    main()
