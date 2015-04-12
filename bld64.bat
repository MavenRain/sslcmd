@echo off
cl cms.c /c /O1 /GS- /Oi-
cl clib.c /c /O1 /GS- /Oi-
link /NODEFAULTLIB /MERGE:.rdata=.text cms.obj clib.obj Shlwapi.lib user32.lib kernel32.lib ws2_32.lib advapi32.lib
copy cms.exe bin\x64\
del *.obj *.err