#Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za> 
#        http://www.distrotech.co.za
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

CFLAGS=-g -Wall -Werror -fpic -I./include
# -static

CORE_LIB_OBJS = refobj.o lookup3.o thread.o
TL_OBJS = taploop.o util.o vlan.o tlsock.o clientserv.o packet.o
TLC_OBJS = tapclient.o

all: libdtsdevcore.so libdtsdevrun.so libdtsdev.a taploopd taploop

install: all
	echo "Put ME Where";

clean:
	rm -f taploop taploopd *.o core

libdtsdevcore.so: $(CORE_LIB_OBJS)
	gcc -g -shared -o $@ $^ -lpthread

libdtsdevrun.so: main.o
	gcc -g -shared -o $@ $^ -L./ -lpthread -ldtsdevcore

libdtsdevcore.a: $(CORE_LIB_OBJS)
	ar rcs $@ $^

libdtsdevrun.a: $(CORE_LIB_OBJS) main.o
	ar rcs $@ $^

taploop: $(TLC_OBJS)
	gcc -g -o $@ $^ -L./ -lpthread

taploopd.a: $(TL_OBJS)
	ar rcs $@ $^

taploopd: libdtsdevrun.a taploopd.a
	gcc -g -o $@ $^ -L./ -lpthread

taploopd.so: $(TL_OBJS)
	gcc -g -o $@ $^ -L./ -lpthread -ldtsdevcore -ldtsdevrun
