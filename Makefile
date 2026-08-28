CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -static -no-pie -s

all: noteVirus stub.bin target

noteVirus: src/protection/protection.c src/replication/replication.c src/infection/infection.c src/main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

stub.bin: src/stub/stub.s
	nasm -f bin -o $@ $<

target: test/target.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f noteVirus stub.bin target

.PHONY: all clean
