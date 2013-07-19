import ctypes, _ctypes
from ctypes import wintypes

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_CREATE_THREAD = 0x0002
MEM_COMMIT = 0x1000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x0004
INFINITE = -1

DEBUG_PROCESS = 0x00000001
CREATE_NEW_PROCESS = 0x00000010

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