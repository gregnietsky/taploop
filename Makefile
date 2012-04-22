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

CFLAGS=-g -Wall -Werror -fpic -I./include -I/usr/include
# -static

CORE_LIB_OBJS = framework/refobj.o framework/lookup3.o framework/thread.o framework/main.o
TL_OBJS = taploopd/taploop.o taploopd/util.o taploopd/vlan.o taploopd/tlsock.o taploopd/clientserv.o taploopd/packet.o
TLC_OBJS = taploopd/tapclient.o

all: framework/libframework.so framework/libframework.a taploopd/taploopd taploopd/taploop

install: all
	echo "Put ME Where";

clean:
	rm -f taploopd/taploop taploopd/taploopd */*.o */*.a */*.so core

framework/libframework.so: $(CORE_LIB_OBJS)
	gcc -g -shared -o $@ $^ -lpthread

framework/libframework.a: $(CORE_LIB_OBJS)
	ar rcs $@ $^

taploopd/taploop: $(TLC_OBJS)
	gcc -g -o $@ $^ -L./ -lpthread

taploopd/taploopd: framework/libframework.a $(TL_OBJS)
	gcc -g -o $@ $^ -L./ -lpthread
