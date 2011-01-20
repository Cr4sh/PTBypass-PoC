@echo off
sc stop PTBypass
sc delete PTBypass
del C:\Windows\system32\drivers\PTBypass.sys
pause
