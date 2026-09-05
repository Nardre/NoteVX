CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Werror
LDFLAGS = -static -no-pie -s

all: noteVirus stub.bin target fakeSection
debug: noteVirus_debug stub.bin target fakeSection_debug

noteVirus: src/propagation/propagation.c src/protection/protection.c src/replication/replication.c src/infection/infection.c src/main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

noteVirus_debug: src/propagation/propagation.c src/protection/protection.c src/replication/replication.c src/infection/infection.c src/main.c
	$(CC) -DDEBUG $(CFLAGS) $(LDFLAGS) -o $@ $^

fakeSection: src/fakeSection/fakeSection.c
	$(CC) $(CFLAGS) -o $@ $<

fakeSection_debug: src/fakeSection/fakeSection.c
	$(CC) -DDEBUG $(CFLAGS) -o $@ $<

stub.bin: src/stub/stub.s
	nasm -f bin -o $@ $<

target: test/target.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f noteVirus noteVirus_debug stub.bin target fakeSection_debug fakeSection

.PHONY: all clean
