@echo off
set SRCPATH=PTBypass.sys
set DSTPATH=C:\Windows\system32\drivers\PTBypass.sys
copy %SRCPATH% %DSTPATH% /Y
sc create PTBypass binPath= %DSTPATH% type= kernel
sc start PTBypass
pause
