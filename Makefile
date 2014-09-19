CC=/usr/bin/gcc
CFLAGS=-W -Wall -ansi -pedantic
LFLAGS=
EXEC=floodit

all: $(EXEC)

floodit: floodit.o main.o
	$(CC) -o $@ $^ $(LFLAGS)

floodit.o: floodit.c
	$(CC) -o $@ -c $< $(CFLAGS)

main.o: main.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf *.o
