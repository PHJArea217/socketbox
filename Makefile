CC ?= gcc
CCLD ?= $(CC)
CFLAGS ?= -fvisibility=hidden -Wall -O2 -fcf-protection=full -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2
CCLDFLAGS ?= -Wl,-z,relro -Wl,-z,now
all: socketbox socketbox-inetd socketbox-inetd-p socketbox-relay send-receive-fd socket-query libsocketbox-preload.so run-with-socketbox
socketbox: unix_scm_rights.o config_parser.o server.o lookup.o libsocketbox.o
	$(CCLD) $(CCLDFLAGS) -g -o $@ $^
socketbox-inetd: socketbox-inetd.o unix_scm_rights.o libsocketbox.o
	$(CCLD) $(CCLDFLAGS) -g -o $@ $^
socketbox-inetd-p: socketbox-inetd-p.o unix_scm_rights.o libsocketbox.o
	$(CCLD) $(CCLDFLAGS) -g -o $@ $^
socketbox-relay: socketbox-relay.o unix_scm_rights.o libsocketbox.o
	$(CCLD) $(CCLDFLAGS) -g -o $@ $^
send-receive-fd: send-receive-fd.o unix_scm_rights.o libsocketbox.o
	$(CCLD) $(CCLDFLAGS) -g -o $@ $^
socket-query: socket-query.o
	$(CCLD) $(CCLDFLAGS) -g -o $@ $^
libsocketbox-preload.so: socketbox-preload.o unix_scm_rights.o libsocketbox.o
	$(CCLD) -shared $(CCLDFLAGS) -g -o $@ $^ -ldl
run-with-socketbox: libsocketbox-preload.so
	./make-ld-preload-script $^ > $@
	chmod +x $@
%.o: %.c
	$(CC) $(CFLAGS) -g -c -o $@ $<
clean:
	rm -f socketbox socketbox-inetd socketbox-inetd-p socketbox-relay send-receive-fd socket-query run-with-socketbox libsocketbox-preload.so *.o
strip:
	strip socketbox socketbox-inetd socketbox-inetd-p socketbox-relay send-receive-fd socket-query libsocketbox-preload.so
.PHONY: all clean strip
