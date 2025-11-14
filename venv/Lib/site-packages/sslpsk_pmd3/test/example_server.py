from __future__ import print_function

import socket
import ssl

import sslpsk_pmd3

PSKS = {'client1' : b'abcdef',
        'client2' : b'123456'}

def server(host, port):
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((host, port))
    tcp_sock.listen(1)

    sock, _ = tcp_sock.accept()
    ssl_sock = sslpsk_pmd3.wrap_socket(sock,
                                       server_side = True,
                                       ssl_version=ssl.PROTOCOL_TLSv1,
                                       ciphers='ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH',
                                       psk=lambda identity: PSKS[identity],
                                       hint=b'server1')

    msg = ssl_sock.recv(4).decode()
    print('Server received: %s'%(msg))
    msg = "pong"
    ssl_sock.sendall(msg.encode())

    ssl_sock.shutdown(socket.SHUT_RDWR)
    ssl_sock.close()

def main():
    host = '127.0.0.1'
    port = 6000
    server(host, port)

if __name__ == '__main__':
    main()
