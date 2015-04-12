@echo off
cl cms.c /c /GS- /O1 /Oi-
cl clib.c /c /GS- /O1 /Oi-
link /NODEFAULTLIB /MERGE:.rdata=.text cms.obj clib.obj Shlwapi.lib user32.lib kernel32.lib ws2_32.lib advapi32.lib
copy cms.exe bin\x86\
del *.obj *.err