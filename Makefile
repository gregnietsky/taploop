#
# Makefile for the SESSION netfilter module
#

CFLAGS=-g -Wall -I./include

TL_OBJS = taploop.o refobj.o

all: taploop

install: all
	echo "Put ME Where";

clean:
	rm -f taploop *.o core

taploop: $(TL_OBJS)
	gcc -g -o $@ $^ -lpthread
