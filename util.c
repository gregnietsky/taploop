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

