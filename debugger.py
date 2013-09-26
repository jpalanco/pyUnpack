from ctypes import *
from ctypes import wintypes
from defines import *

kernel32 = ctypes.WinDLL('kernel32.dll')

class debugger():
    def __init__(self):
        self.hProcess           =   None
        self.pid                =   None
        self.debugger_active    =   None


    def load(self, path_to_malware, path_to_dll):

        creation_flags = CREATE_NEW_PROCESS_SUSPENDED

        startupinfo     = STARTUPINFO()
        process_info    = PROCESS_INFORMATION()
        image_dos_header = IMAGE_DOS_HEADER()

        ptr_to_image_dos_header = ctypes.POINTER(IMAGE_DOS_HEADER)

        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0

        startupinfo.cb = ctypes.sizeof(startupinfo)

        

        #packed_malware = input("Enter the path of the file to unpack: ")
        #print("The malware entered is: %s" % packed_malware)

        dll_len = (len(path_to_dll) + 1) * ctypes.sizeof(wintypes.WCHAR)

        print("[+] trying to launch " + path_to_malware + " in a suspended state...")
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
        print("The TIB of the main thread is: " + str(process_info.dwThreadId));
        print("\n")
        print("[+] sucessfully launched process with the PID: " + str(process_info.dwProcessId) + " in the suspended state.\n")
        print("[+] getting a handle to the process...")
        hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(process_info.dwProcessId))

        if hProcess is None:
            hProcessError = ctypes.WinError(ctypes.get_last_error())
            print("Could not get a handle to the process with the PID: %s" % str(process_info.dwProcessId))
            system.exit(1)
        print("[+] acquired a handle to process: " + str(process_info.dwProcessId) + "\n")

        print("[+] allocating memory in the process...")

        arg_address = kernel32.VirtualAllocEx(hProcess, None, dll_len, MEM_COMMIT, PAGE_READWRITE)

        if arg_address is None:
            arg_addressError = ctypes.WinError(ctypes.get_last_error())
            print("[-] could not allocate memory "+ arg_addressError +" exiting...")
            system.exit(1)

        print("[+] successfully allocated memory into the process\n")

        print("[+] writing the dll into the memory")
        bSuccess = kernel32.WriteProcessMemory(hProcess, arg_address, path_to_dll, dll_len, byref(written))
        #print("....the number of bytes written into the process is: " + str()

        if bSuccess is False:
            bSucces_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error writing the dll into memory " + bSuccess_Error + " exiting...")
            system.exit(1)
        print("[+] successfully wrote the dll into memory\n")
        

        hKernel32 = kernel32.GetModuleHandleW('kernel32.dll')
        if hKernel32 is None:
            hKernel32_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error getting a handle to kernl32.dll" + hKernel32_Error + " exiting...")
            system.exit(1)
            
        print("[+] The address for the kernel handle is %s" % hex(hKernel32))

        hLoadlib = kernel32.GetProcAddress(hKernel32, b"LoadLibraryW")
        if hLoadlib is None:
            hLoadlib_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error getting the proc address to loadlibrary " + hLoadlib_Error + " exiting...")
            system.exit(1)
        
        print("[+] The address of the loadlibraryW is %s" % hex(hLoadlib))

        print("[+] injecting dll by creating a remote thread in the process...")
        hThread = kernel32.CreateRemoteThread(hProcess,
                                       None, 
                                       0, 
                                       hLoadlib, 
                                       arg_address, 
                                       0, 
                                       byref(thread_id))

        if hThread is None:
            hThread_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error creating the remote thread and injecting the dll " + hThread_Error + " exiting...")
            system.exit(1)

        print("[+] sucessfully created the thread " + str(thread_id.value) + " into process " + str(process_info.dwProcessId) + "\n")

        print("[+] resuming the injected thread...")
        dwPrevSuspendCount = kernel32.ResumeThread(hThread)

        if dwPrevSuspendCount == -1:
            dwPrevSuspendCount_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error running the thread " + dwPrevSuspendCount_Error + " exiting...")
            system.exit(1)
        
        print("[+] successfully ran the injected dll")

        print("[+] dereferencing to get the IAT...")

        hModule = kernel32.GetModuleHandleW(0)

        if hModule == 0:
            hModule_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error getting the hModule to the running process " + hModule)
            system.exit(1)

        print("[+] The address for the kernel handle is %s" % hex(hModule))

        ptr_to_image_dos_header = ctypes.cast(hModule, ctypes.POINTER(IMAGE_DOS_HEADER)).contents

        print("[+] successfully got the address to the IAT")

        print("[+] patching the import address table to hook the API...")

        print("[+] successfully patched the IAT")

        print("[+] resuming the main thread...")

        dwPrevSuspendCount = kernel32.ResumeThread(process_info.hThread)

        if dwPrevSuspendCount == -1:
            dwPrevSuspendCount_Error = ctypes.WinError(ctypes.get_last_error())
            print("[-] error running the main thread " + dwPrevSuspendCount_Error + " exiting...")
            system.exit(1)

        print("[+] successfully ran the main thread")

        bTermProcess = kernel32.TerminateProcess(hProcess, 0)

        
