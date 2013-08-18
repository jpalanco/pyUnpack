from ctypes import *
from ctypes import wintypes
from defines import *

kernel32 = ctypes.WinDLL('kernel32.dll')

class debugger():
    def __init__(self):
        self.hProcess           =   None
        self.pid                =   None
        self.debugger_active    =   None


    def load(self, path_to_malware):
        creation_flags = CREATE_NEW_PROCESS_SUSPENDED

        startupinfo     = STARTUPINFO()
        process_info    = PROCESS_INFORMATION()

        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        startupinfo.cb = ctypes.sizeof(startupinfo)

        kernel32.CreateProcessW.restype = wintypes.BOOL
        kernel32.CreateProcessW.argtypes = [
            wintypes.LPCWSTR,   # lpApplicationName
            LPTSTR,             # lpCommandLine
            wintypes.LPSTR,     # lpProcessAttributes
            wintypes.LPVOID,    # lpThreadAttributes
            wintypes.BOOL,      # bInheritHandles
            wintypes.DWORD,     # dwCreationFlags
            wintypes.LPVOID,    # lpEnvironment
            wintypes.LPCWSTR,   # lpCurrentDirectory
            wintypes.LPVOID,    # lpStartupInfo
            wintypes.LPVOID     # lpProcessInformation 
        ]

        #packed_malware = input("Enter the path of the file to unpack: ")
        #print("The malware entered is: %s" % packed_malware)

        bCreateProcessW = kernel32.CreateProcessW(
                                    path_to_malware,
                                    None,
                                    None,
                                    None,
                                    True,
                                    creation_flags,
                                    None,
                                    None,
                                    byref(startupinfo),
                                    byref(process_info))

        if bCreateProcessW is None:
            createProcessError = ctypes.WinError(ctypes.get_last_error())
            print("Could not CreateProcessW: " + path_to_malware + " the getLastError() is: " + createProcessError)
            system.exit(1)

        print("\n")
        print("[+] sucessfully launched process with the PID: " + str(process_info.dwProcessId) + " in the suspended state.")
        print("[+] getting a handle to the process...")
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(process_info.dwProcessId))

        if hProcess is None:
            hProcessError = ctypes.WinError(ctypes.get_last_error())
            print("Could not get a handle to the process with the PID: %s" % str(process_info.dwProcessId))
            system.exit(1)
        print("[+] acquired a handle to process: " + str(process_info.dwProcessId))

        print("[+] allocating memory into the process")

        #Have to the dll_len once we realize what dll we are going to inject
        #arg_address = kernel32.VirtualAllocEx(hProcess, None, dll_len, MEM_COMMIT, PAGE_READWRITE)
        arg_address = kernel32.VirtualAllocEx(hProcess, None, 10, MEM_COMMIT, PAGE_READWRITE)

        if arg_address is None:
            arg_addressError = ctypes.WinError(ctypes.get_last_error())
            print("[-] could not allocate memory "+ arg_addressError +" exiting...")
            system.exit(1)

        print("[+] successfully allocated memory into the process")

        print("[+] writing the dll into the memory")
        #bSuccess = kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))

        #if bSuccess is False:
            #bSuccesError = ctypes.WinError(ctypes.get_last_error())
            #print("[-] error writing the dll into memory " + bSuccessError + " exiting...")

        print("[+] injecting dll...")

        bTermProcess = kernel32.TerminateProcess(hProcess, 0)

        
