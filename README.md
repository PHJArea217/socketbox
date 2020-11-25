socketbox -- single socket, multiple daemons

socketbox is an alternative to the classic "inetd" daemon. Similar to inetd,
socketbox allows you to spawn daemons on-demand on every connection made to a
server. However, socketbox is much more flexible than traditional inetd in that
the accepted sockets are passed on to other daemons using UNIX domain sockets
(the SCM\_RIGHTS control message).

One advantage of passing the sockets onto another program using a UNIX domain
socket is that the other program can be in a completely different environment.
More specifically, the other program can be in an LXC or Docker container, or
some other environment where the network namespace is different. This allows
daemons in other network namespaces to accept connections that would only be
available from the host, even if the network namespace is completely isolated.

socketbox consists of two main components:

* The socketbox server, which accepts TCP connections like any other network
daemon, but passes the socket onto a client as described below, using the
SCM\_RIGHTS control message.
* Any one of \(currently) three socketbox clients, which accept the sockets
from the socketbox server.

The available clients are:

* socketbox-inetd is the safest, but requires that the daemon using it have an
"inetd mode" or equivalent \(e.g. sshd -i).
* socketbox-preload is an LD\_PRELOAD library that intercepts the "listen" and
"accept" system calls, allowing virtually any TCP server daemon to take
advantage of socketbox. This is the most compatible, but like all LD\_PRELOAD
libraries, things can break.
* socketbox-relay is a native client. A socket relay was chosen because it can
be used to proxy to virtually any other server, but can incur slight overhead,
especially if the end server is on the same system as the socketbox daemon.

Another remarkable feature of socketbox is the ability to control where the
socket is sent just by the server IP address. The intended use case for this
is when the
[AnyIP](https://www.peterjin.org/wiki/Snippets:Nginx_geo_local_server_address)
trick is used, and a set of rules dictate where the socket is sent based on the
server IP address. Since 2001:db8::1 and 2001:db8::2 would normally refer to
two different hosts, if sockets to 2001:db8::1 go to one daemon and sockets to
2001:db8::2 go to another, then it will just be like they were on different
systems, only that socketbox is much more flexible in terms of routing.

Other features include:
* Single server socket \(ip\[6]tables TPROXY should be used for multiple ports)
* Separation of socket acceptor and server logic allows the server daemon to
run fully unprivileged
* Load balancing via the SO\_REUSEPORT option \(untested)
* Sends the original socket, not a proxied version of it, so the daemon can
achieve full native performance and see the client IP address
* Adds \(potentially transparent) IPv6 support to IPv4-only daemons

socketbox is IPv6-only by design, since the AnyIP trick works best over IPv6
due to its abundance of addresses. It can work with IPv4, as long as you
prefix the address with ::ffff:.

# Command-line options

* -f[]: configuration file (default /etc/socketbox.conf)
* -l[]: listen IPv6 address, usually INADDR6\_ANY (::) or a specific address
specified by ```-j TPROXY --on-ip```
* -p[]: Listening socket port number
* -t: Set IPV6\_TRANSPARENT
* -F: Set IPV6\_FREEBIND
* -R: Clear SO\_REUSEADDR
* -r: Set SO\_REUSEPORT
* -s[]: Inherit socket from specified file descriptor. Useful if called from
another program with an inherited file descriptor.
* -e: Run the specified program instead of socketbox; envvar SKBOX_LISTEN_FD
can be used to retrieve the inherited socket.
* -u[]: Run as user/UID. The options specified by -u, -g, and -G must allow
read/write access to any sockets provided in the configuration file.
* -g[]: Run as group/GID
* -G[]: List of groups to keep in supplementary group list.
* -k: Don't change groups
* -x[]: Chroot directory
* -S[]: Just send it to the specified Unix domain socket instead of parsing
rules
* -i[]: Send it to the file descriptor instead of parsing rules
