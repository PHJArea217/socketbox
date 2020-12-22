#!/usr/bin/python3

my_addr = bytes.from_hex("20010db8000000010001")

import socket
import array
import os
rainbow_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
rainbow_socket.setsockopt(41, 75, 1) # IPV6_TRANSPARENT
rainbow_socket.bind(("::ffff:127.100.100.2", 1))

os.chroot("/sockets")
os.setgroups([])
os.setgid(100)
os.setuid(106)

rainbow_socket.listen()

unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
while True:
    (accept_socket, remote_addr) = rainbow_socket.accept()
    try:
        accept_socket.setsockopt(41, 75, 0) # IPV6_TRANSPARENT
        (local_addr, local_port) = accept_socket.getsockname()
        local_addr_buffer = socket.inet_pton(socket.AF_INET6, local_addr)
        if local_addr_buffer[0:10] == my_addr:
            next_part = int.from_bytes(local_addr_buffer[10:12], "big")
            local_part = 0
            if next_part == 0:
                local_part = int.from_bytes(local_addr_buffer[12:16], "big")
                target_sockname = "/s0_%d/p_%d" % (local_part, local_port)
            else:
                target_sockname = "/s_%d/i_%d" % (next_part, local_port)

            unix_socket.sendmsg([b'\0'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [accept_socket.fileno()]))], socket.MSG_NOSIGNAL, target_sockname)
    except:
        pass
    finally:
        accept_socket.close()
