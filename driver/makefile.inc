
driver.obj: src/driver.cpp
    $(CC) $(CFLAGS) src/driver.cpp

xde.obj: src/xde/xde.cpp
    $(CC) $(CFLAGS) src/xde/xde.cpp
    
hook.obj: src/hook.cpp
    $(CC) $(CFLAGS) src/hook.cpp    

debug.obj: src/r0_common/debug.cpp
    $(CC) $(CFLAGS) src/r0_common/debug.cpp

common.obj: src/r0_common/common.cpp
    $(CC) $(CFLAGS) src/r0_common/common.cpp

LLIBS = ntoskrnl.lib hal.lib

LOBJS = driver.obj xde.obj hook.obj debug.obj common.obj
