/*
Copyright (C) 2012  Gregory Nietsky <gregory@distrotetch.co.za> 
        http://www.distrotech.co.za

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "refobj.h"

void setflag(void *obj, void *flag, int flags) {
        int *flg = flag;
        objlock(obj);
        *flg |= flags;
        objunlock(obj);
}

void clearflag(void *obj, void *flag, int flags) {
        int *flg = flag;
        objlock(obj);
        *flg &= ~flags;
        objunlock(obj);
}

int testflag(void *obj, void *flag, int flags) {
        int *flg = flag;
        int ret = 0;
        objlock(obj);
        ret = (*flg & flags) ? 1 : 0;
        objunlock(obj);
        return ret;
}

