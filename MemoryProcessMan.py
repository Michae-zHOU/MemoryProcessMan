import os.path

from WinPyApi import *

HEX_ADDRESS_OFFSET = 0x01010000
MAX_PATH = 260


class MemoryProcessMan:

    def __init__(self):
        """
        Default constructor
        """
        self.pName = ""
        self.pid = 0
        self.hProcess = None

    def getname(self):
        """
        Getter of Process Name
        :return: Process Name String
        """
        return self.pName

    def get_process_id(self):
        """
        Getter of Process Identifier
        :return: Process Identifier
        """
        return self.pid

    def get_process_handle(self):
        """
        Getter of Process Handle
        :return: Process Handle
        """
        return self.hProcess

    def Initialize(self, pName):
        """
        Initialize the Object and Process Connection
        :param pName: Process Name
        :return: None
        """
        self.GetProcessIdByName(pName)
        if self.OpenProcess() == -1:
            print("Failure: Open Process")

    def GetProcessIdByName(self, pName):
        """
        Get Process Identifier by Name
        :param pName: Process Name
        :return: Process Identifier
        """
        if pName.endswith('.exe'):
            pass
        else:
            pName = pName + '.exe'

        self.pName = pName
        ProcessIds, BytesReturned = self.EnumProcesses()

        for index in list(range(int(BytesReturned / sizeof(DWORD)))):
            ProcessId = ProcessIds[index]
            hProcess = get_process_handle(ProcessId, PROCESS_QUERY_INFORMATION)
            if hProcess:
                ImageFileName = (ctypes.c_char * MAX_PATH)()
                if get_image_filename(hProcess, ImageFileName, MAX_PATH) > 0:
                    filename = os.path.basename(ImageFileName.value)
                    if filename.decode('utf-8') == pName:
                        self.pid = ProcessId
                        return ProcessId
                self.CloseHandle(hProcess)
        return -1

    """
    Enumrate the Processes running in task manager
    """

    def EnumProcesses(self):
        if enumerate_processes() is not None:
            return enumerate_processes()
        else:
            print("No Processes Found.")

    def OpenProcess(self):
        """
        Open Process Connection
        :return: Process Handle
        """
        hProcess = get_process_handle(self.pid, PROCESS_ALL_ACCESS)
        if hProcess:
            self.hProcess = hProcess
        else:
            return None

    def CloseHandle(self, hProcess):
        """
        Close the Process Handle
        :param hProcess: Process Handle
        :return: None
        """
        try:
            close_process_handle(hProcess)
        except Exception:
            print(Exception)

    def getPointer(self, hProcess, lpBaseAddress, offsets):
        """
        Retrieve Pointer from Address
        :param hProcess: Process Handle
        :param lpBaseAddress: Address to Retrieve Pointer
        :param offsets: Pointer Size Offset
        :return: Pointer Value
        """
        pointer = self.ReadProcessMemory(lpBaseAddress)
        if offsets == None:
            return lpBaseAddress
        elif len(offsets) == 1:
            result = int(str(pointer), 0) + int(str(offsets[0]), 0)
            return result
        else:
            count = len(offsets)
            for i in offsets:
                count -= 1
                result = int(str(pointer), 0) + int(str(i), 0)
                pointer = self.ReadProcessMemory(result)
                if count == 1:
                    break
            return pointer

    def ReadProcessMemory(self, lpBaseAddress):
        """
        Read the Process Memory by lpBaseAddress
        :param lpBaseAddress: Address to Read Value
        :return: Value Read from the Address
        """
        try:
            read_memory_buffer = read_buffer(self.hProcess, lpBaseAddress, ctypes.sizeof(ctypes.c_uint()))
            return read_memory_buffer
        except Exception:
            self.CloseHandle(self.hProcess)
            print(Exception)

    def WriteProcessMemory(self, lpBaseAddress, value):
        """
        Write the Process Memory by lpBaseAddress and value
        :param lpBaseAddress: Address to Write Value
        :param value: Value to be Written
        :return: Status
        """
        try:
            status = write_buffer(self.hProcess, lpBaseAddress, value, ctypes.sizeof(value))
            return status
        except Exception:
            self.CloseHandle(self.hProcess)
            print(Exception)
            return False

    def GetLastError(self):
        """
        Get the Error Status
        :return: Error Status
        """
        return GetLastError()


def main():
    memory_process_handle = MemoryProcessMan()
    memory_process_handle.Initialize("Spotify.exe")

    rd_start = 1
    rd_end = 1000
    for rd_idx in range(rd_start, rd_end):
        rd_buff = memory_process_handle.ReadProcessMemory(HEX_ADDRESS_OFFSET + rd_idx)
        print(rd_buff)


if __name__ == '__main__':
    main()
