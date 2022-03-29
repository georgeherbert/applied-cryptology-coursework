EXE=attack

CC=gcc
CFLAGS=-Wall -std=gnu99 -O3 -mtune=native
LIBS=-lgmp -lcrypto -lm

all: $(EXE)

$(EXE): $(EXE).c
	$(CC) $(CFLAGS) $^ $(LIBS) -o $@

clean:
	rm -f $(EXE)