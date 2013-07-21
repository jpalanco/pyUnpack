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
        creation_flags = DEBUG_PROCESS

        startupinfo     = STARTUPINFO()
        process_info    = PROCESS_INFORMATION()

        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        startupinfo.cb = ctypes.sizeof(startupinfo)

        kernel32.CreateProcessW.restype = wintypes.BOOL
        kernel32.OpenProcess.argtypes = [
            wintypes.LPCWSTR,   # lpApplicationName
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

        bCreateProcessW = kernel32.CreateProcessW(path_to_malware,
                                    None,
                                    None,
                                    None,
                                    None,
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
        print("[+] sucessfully launched process with the PID: %s" % process_info.dwProcessId)
        print("[+] injecting dll...")
        #self.hProcess = self.open_process(process_info.dwProcessId)
        print("[+] acquired a handle to the process!")

    def open_process(self, pid):
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, pid, false)
        return hProcess
        
