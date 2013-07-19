import ctypes, _ctypes
from ctypes import wintypes
from defines import *

kernel32 = ctypes.WinDLL('kernel32.dll')

class debugger():
    def __init__(self):
        pass


    def load(self, path_to_malware):
        creation_flags = DEBUG_PROCESS

        startupinfo     = STARTUPINFO()
        process_info    = PROCESS_INFORMATION()

        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        startupinfo.cb = sizeof(startupinfo)

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

        packed_malware = input("Enter the path of the file to unpack: ")
        print("The malware entered is: %s" % packed_malware)

        if kernel32.CreateProcessW(path_to_exe,
                                    None,
                                    None,
                                    None,
                                    None,
                                    creation_flags,
                                    None,
                                    None,
                                    POINTER(startupinfo),
                                    POINTER(process_info)):
            print("Sucessfully created process")
        else:
            createProcessError = ctypes.WinError(ctypes.get_last_error())
            print("The CreateProcessW error was: %s" % createProcessError)