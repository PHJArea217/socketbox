CFLAGS ?= -fvisibility=hidden
all: socketbox socketbox-inetd socketbox-relay send-receive-fd socket-query libsocketbox-preload.so
socketbox: unix_scm_rights.o config_parser.o server.o lookup.o
	gcc $(LDFLAGS) -g -o $@ $^
socketbox-inetd: socketbox-inetd.o unix_scm_rights.o libsocketbox.o
	gcc $(LDFLAGS) -g -o $@ $^
socketbox-relay: socketbox-relay.o unix_scm_rights.o libsocketbox.o
	gcc $(LDFLAGS) -g -o $@ $^
send-receive-fd: send-receive-fd.o unix_scm_rights.o
	gcc $(LDFLAGS) -g -o $@ $^
socket-query: socket-query.o
	gcc $(LDFLAGS) -g -o $@ $^
libsocketbox-preload.so: socketbox-preload.o unix_scm_rights.o libsocketbox.o
	gcc -shared $(LDFLAGS) -g -o $@ $^ -ldl
%.o: %.c
	gcc $(CFLAGS) -g -c -o $@ $<
clean:
	rm -f socketbox socketbox-inetd socketbox-relay send-receive-fd socket-query libsocketbox-preload.so *.o
.PHONY: clean
