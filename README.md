# Pamsi-bypass (Python AMSI bypass)

## How does it work?

So this simple script basically does the same thing that Victor Khoury's bypass does, and that is, find the location of the writable pointer inside System.Automation, then what i do different is instead of simply replacing it with my own dummy, i search for a RET inside the code of ntdll.dll (yes i am very lazy and wanted to skip the calls to VirtualAllocEx to create the dummy function) and replace the address of AmsiScanBuffer with that so the code ends up being basically useless
