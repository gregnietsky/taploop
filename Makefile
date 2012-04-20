#
# Makefile for the SESSION netfilter module
#

CFLAGS=-g -Wall -I./include

TL_OBJS = taploop.o

all: taploop

install:
	echo "Put ME Where";

clean:
	rm -f taploop *.o core

.o:
	gcc -g -c $@

taploop: $(TL_OBJS)
	gcc -g -o $@ $^ -lpthread
