CC = gcc
DFLAGS = -DDEBUG -DDEBUG_ROUNDS -DDEBUG_F_FUNC -DDEBUG_G_FUNC -DDEBUG_K_FUNC
CFLAGS = --std=c99 -Wall --pedantic $(DFLAGS)


all: util.o wsu_crypt.o main.o
	$(CC) util.o wsu_crypt.o main.o -o wsucrypt

wsu_crypt.o: wsu_crypt.c wsu_crypt.h
	$(CC) -c $(CFLAGS) wsu_crypt.c

main.o: main.c wsu_crypt.h
	$(CC) -c $(CFLAGS) main.c

util.o: util.c util.h
	$(CC) -c $(CFLAGS) util.c

.PHONY: clean
clean:
	rm *.o wsucrypt