CC=/usr/bin/gcc
CFLAGS=-W -Wall -ansi -pedantic
LFLAGS=
EXEC=floodit

all: $(EXEC)

floodit: floodit.o
	$(CC) -o $@ $^ $(LFLAGS)

floodit.o: floodit.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o
