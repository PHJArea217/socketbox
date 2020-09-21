all: socketbox socketbox-inetd
socketbox: unix_scm_rights.o config_parser.o server.o lookup.o
	gcc -g -o $@ $^
socketbox-inetd: socketbox-inetd.o unix_scm_rights.o libsocketbox.o
	gcc -g -o $@ $^
%.o: %.c
	gcc -g -c -o $@ $<
clean:
	rm -f socketbox socketbox-inetd *.o
.PHONY: clean
