# Makefile for mhttping tcp app

CC=gcc
CFLAGS=-g -Wall

all:
	$(CC) $(CFLAGS) mhttping.c -o mhttping -lm -lpthread

install:
	sudo cp mhttping /usr/bin/
	sudo mkdir -p /var/www/web
clean:
	sudo rm -f mhttping
	sudo rm -rf mhttping.dSYM
	sudo rm -f /usr/bin/mhttping
