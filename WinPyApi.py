import ctypes
import ctypes.wintypes
from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPCVOID
from ctypes.wintypes import LPSTR
from ctypes.wintypes import LPVOID

LPCSTR = LPCTSTR = ctypes.c_char_p
LPDWORD = PDWORD = ctypes.POINTER(DWORD)


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL), ]


SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = LPVOID

DELETE = 0x00010000  # Required to delete the object.
READ_CONTROL = 0x00020000  # Required to read information in the security descriptor for the object, not including the information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right. For more information, see SACL Access Right.
SYNCHRONIZE = 0x00100000  # The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
WRITE_DAC = 0x00040000  # Required to modify the DACL in the security descriptor for the object.
WRITE_OWNER = 0x00080000  # Required to change the owner in the security descriptor for the object.
PROCESS_CREATE_PROCESS = 0x0080  # Required to create a process.
PROCESS_CREATE_THREAD = 0x0002  # Required to create a thread.
PROCESS_DUP_HANDLE = 0x0040  # Required to duplicate a handle using DuplicateHandle.
PROCESS_QUERY_INFORMATION = 0x0400  # Required to retrieve certain information about a process, such as its token, exit code, and priority class = see OpenProcessToken #.
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.
PROCESS_SET_INFORMATION = 0x0200  # Required to set certain information about a process, such as its priority class = see SetPriorityClass #.
PROCESS_SET_QUOTA = 0x0100  # Required to set memory limits using SetProcessWorkingSetSize.
PROCESS_SUSPEND_RESUME = 0x0800  # Required to suspend or resume a process.
PROCESS_TERMINATE = 0x0001  # Required to terminate a process using TerminateProcess.
PROCESS_VM_OPERATION = 0x0008  # Required to perform an operation on the address space of a process = see VirtualProtectEx and WriteProcessMemory #.
PROCESS_VM_READ = 0x0010  # Required to read memory in a process using ReadProcessMemory.
PROCESS_VM_WRITE = 0x0020  # Required to write to memory in a process using WriteProcessMemory.
PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE

PROCESS_COUNT_OFFSET = 0x32
PROCESS_INCREMENT_OFFSET = 0x2

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x1000000
MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

EXECUTE_IMMEDIATELY = 0x00000000
CREATE_SUSPENDED = 0x00000004
STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = (DWORD, BOOL, DWORD)

VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
VirtualAllocEx.restype = LPVOID
VirtualAllocEx.argtypes = (HANDLE, LPVOID, DWORD, DWORD, DWORD)

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = BOOL
ReadProcessMemory.argtypes = (HANDLE, LPCVOID, LPVOID, DWORD, DWORD)

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = BOOL
WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, DWORD, DWORD)

CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
CreateRemoteThread.restype = HANDLE
CreateRemoteThread.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)

GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = DWORD
GetLastError.argtypes = ()

GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleA
GetModuleHandle.restype = HANDLE
GetModuleHandle.argtypes = (LPCTSTR,)

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = LPVOID
GetProcAddress.argtypes = (HANDLE, LPCTSTR)

GetProcessImageFileNameA = ctypes.windll.psapi.GetProcessImageFileNameA
GetProcessImageFileNameA.restype = DWORD
GetProcessImageFileNameA.argtypes = (HANDLE, LPSTR, DWORD)

EnumProcesses = ctypes.windll.Psapi.EnumProcesses
EnumProcesses.restype = BOOL
EnumProcesses.argtypes = (LPVOID, DWORD, LPDWORD)

byref = ctypes.byref
sizeof = ctypes.sizeof


def get_process_handle(dwProcessId, dwDesiredAccess, bInheritHandle=False):
    handle = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if dwDesiredAccess is not PROCESS_QUERY_INFORMATION:
        if handle is None or handle == 0:
            raise Exception('Error: %s' % GetLastError())

    return handle


def close_process_handle(hProcess):
    try:
        ctypes.windll.kernel32.CloseHandle(hProcess)
    except Exception:
        raise Exception


def allocate(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
    lpBuffer = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    if lpBuffer is None or lpBuffer == 0:
        raise Exception('Error: %s' % GetLastError())

    return lpBuffer


def read_buffer(hProcess, lpBaseAddress, nSize):
    dwNumberOfBytesRead = ReadProcessMemory.argtypes[-1]()
    lpBuffer = ctypes.create_string_buffer(nSize)
    result = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.addressof(dwNumberOfBytesRead))
    if result is None or result == 0:
        raise Exception('Error: %s' % GetLastError())

    if dwNumberOfBytesRead.value != nSize:
        raise Exception('Read %s bytes when %s bytes should have been read' % (dwNumberOfBytesRead.value, nSize))

    return lpBuffer.raw


def write_buffer(hProcess, lpBaseAddress, lpBuffer, nSize):
    dwNumberOfBytesWritten = WriteProcessMemory.argtypes[-1]()
    result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.addressof(dwNumberOfBytesWritten))
    if result is None or result == 0:
        raise Exception('Error: %s' % GetLastError())

    if dwNumberOfBytesWritten.value != nSize:
        raise Exception('Wrote %s bytes when %s bytes should have been written' % (dwNumberOfBytesWritten.value, nSize))


def allocate_and_write(hProcess, lpAddress, dwSize, flAllocationType, flProtect, lpBuffer):
    lpStartAddress = allocate(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    write_buffer(hProcess, lpStartAddress, lpBuffer, dwSize)

    return lpStartAddress


def create_thread(hProcess, lpStartAddress, dwStackSize=0, lpParameter=0, dwCreationFlags=EXECUTE_IMMEDIATELY,
                  lpThreadId=0, lpSecurityDescriptor=0, bInheritHandle=False):
    ThreadAttributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), lpSecurityDescriptor, bInheritHandle)
    lpThreadAttributes = LPSECURITY_ATTRIBUTES(ThreadAttributes)
    handle = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags,
                                lpThreadId)

    if handle is None or handle == 0:
        raise Exception('Error: %s' % GetLastError())

    return handle


def enumerate_processes():
    count = PROCESS_COUNT_OFFSET
    while True:
        ProcessIds = (DWORD * count)()
        cb = sizeof(ProcessIds)
        BytesReturned = DWORD()
        if EnumProcesses(byref(ProcessIds), cb, byref(BytesReturned)):
            if BytesReturned.value < cb:
                return ProcessIds, BytesReturned.value
            else:
                count *= PROCESS_INCREMENT_OFFSET
        else:
            return None


def get_image_filename(hProcess, lpImageFileName, nSize):
    try:
        return GetProcessImageFileNameA(hProcess, lpImageFileName, nSize)
    except:
        return None
