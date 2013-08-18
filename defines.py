import ctypes, _ctypes
from ctypes import wintypes

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_CREATE_THREAD = 0x0002
PROCESS_ALL_ACCESS      =   ( 0x000F0000 | 0x00100000 | 0xFFF )
MEM_COMMIT = 0x1000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x0004
INFINITE = -1

written = ctypes.c_int(0)

DEBUG_PROCESS = 0x00000001
CREATE_NEW_PROCESS_DEBUG = 0x00000010
CREATE_NEW_PROCESS_SUSPENDED = 0x00000004

SIZE_T = ctypes.c_size_t
WCHAR_SIZE = ctypes.sizeof(wintypes.WCHAR)
LPSECURITY_ATTRIBUTES = wintypes.LPVOID
LPTHREAD_START_ROUTINE = wintypes.LPVOID
WORD    = ctypes.c_short
DWORD   = ctypes.c_ulong
LPBYTE  = ctypes.POINTER(ctypes.c_ubyte)
LPTSTR  = ctypes.POINTER(ctypes.c_char)
HANDLE  = ctypes.c_void_p

#Struct for CreateProcessA
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
                ("cb",          DWORD),
                ("lpReserved",  LPTSTR),
                ("lpDesktop",   LPTSTR),
                ("lpTitle",     wintypes.LPSTR),
                ("dwX",         DWORD),
                ("dwY",         DWORD),
                ("dwXSize",     DWORD),
                ("dwYSize",     DWORD),
                ("dwXCountChars",   DWORD),
                ("dwFillAttribute", DWORD),
                ("dwFlags",     DWORD),
                ("wShowWindow", WORD),
                ("cbReserved2", WORD),
                ("lpReserved2", LPBYTE),
                ("hStdInput",   HANDLE),
                ("hStdOutput",  HANDLE),
                ("hStdI",       HANDLE),
                ]

class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
                ("hProcess",    HANDLE),
                ("hThread",     HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId",  DWORD),
                ]

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD, # dwDesiredAccess
    wintypes.BOOL,  # bInheritHandle
    wintypes.DWORD, # dwProcessId
]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.CreateProcessW.argtypes = [
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
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE, # hProcess
    wintypes.LPVOID, # lpAddress
    SIZE_T, # dwSize
    wintypes.DWORD,  # flAllocationType
    wintypes.DWORD, # flProtect
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL
kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE, # hProcess
    wintypes.LPVOID, # lpAddress
    SIZE_T, # dwSize
    wintypes.DWORD,  # dwFreeType
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,  # hProcess
    wintypes.LPVOID,  # lpBaseAddress
    wintypes.LPCVOID, # lpBuffer
    SIZE_T,  # nSize
    ctypes.POINTER(SIZE_T), # lpNumberOfBytesWritten _Out_
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,  # hProcess
    LPSECURITY_ATTRIBUTES,  # lpThreadAttributes
    SIZE_T,  # dwStackSize
    LPTHREAD_START_ROUTINE, # lpStartAddress
    wintypes.LPVOID,  # lpParameter
    wintypes.DWORD,   # dwCreationFlags
    wintypes.LPDWORD, # lpThreadId _Out_
]

kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.TerminateProcess.argtypes = [
    wintypes.HANDLE,    #hProcess
    wintypes.UINT       #uExitCode
]