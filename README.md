# CheckBitness
A simple utility to verify an executable is valid and check whether 32bit/64bit

![image](https://github.com/fafalone/CheckBitness/assets/7834493/a2193090-8835-45b4-bdbb-23df50a26218)


Since twinBASIC supports 64bit, there's more of a reason than ever to check whether an exe or dll is 32bit or 64bit. I was playing around with PE file headers the past few days and decide to turn this into a little demo. There's not much to it, just pick a file, and it tells you if it's 32bit, 64bit AMD64, 64bit IA64, or 64bit ARM64 (for newer Windows on ARM devices); or lets you know if there's a different signature or it couldn't process the file at all.

## How it works

(Overview only, needs full code to run)

The key is a couple headers at the start of all Windows executable (PE format) files

```vb6
Public Type IMAGE_DOS_HEADER ' DOS .EXE header
    e_magic As Integer ' Magic number
    e_cblp As Integer ' Bytes on last page of file
    e_cp As Integer ' Pages in file
    e_crlc As Integer ' Relocations
    e_cparhdr As Integer ' Size of header in paragraphs
    e_minalloc As Integer ' Minimum extra paragraphs needed
    e_maxalloc As Integer ' Maximum extra paragraphs needed
    e_ss As Integer ' Initial (relative) SS value
    e_sp As Integer ' Initial SP value
    e_csum As Integer ' Checksum
    e_ip As Integer ' Initial IP value
    e_cs As Integer ' Initial (relative) CS value
    e_lfarlc As Integer ' File address of relocation table
    e_ovno As Integer ' Overlay number
    e_res(0 To 3) As Integer ' Reserved words
    e_oemid As Integer ' OEM identifier (for e_oeminfo)
    e_oeminfo As Integer ' OEM information; e_oemid specific
    e_res2(0 To 9) As Integer ' Reserved words
    e_lfanew As Long ' File address of new exe header
End Type

Public Type IMAGE_FILE_HEADER
    Machine As Integer
    NumberOfSections As Integer
    TimeDateStamp As Long
    PointerToSymbolTable As Long
    NumberOfSymbols As Long
    SizeOfOptionalHeader As Integer
    Characteristics As Integer
End Type

Public Type IMAGE_NT_HEADERS
    Signature As Long
    FileHeader As IMAGE_FILE_HEADER
    OptionalHeader As IMAGE_OPTIONAL_HEADER
End Type
```

>[!NOTE]
>There's different `IMAGE_OPTIONAL_HEADER` types for 32 and 64bit because of pointer size differences, and subsequently different `IMAGE_NT_HEADERS`, but we don't worry about that for this check because we only need the `IMAGE_FILE_HEADER` and `IMAGE_DOS_HEADER`, which are the same on both 32bit and 64bit.

All of those definitions, and the omitted enums and constants, are included in tbShellLib. With those defs, here's what we do:

1. Load the file with `CreateFile` and map it into memory with `CreateFileMapping/MapViewOfFile`
2. The mapping gives us a base address, from which we copy the `IMAGE_DOS_HEADER`
3. We check the magic number: It should be 'MZ', i.e. `IMAGE_DOS_SIGNATURE  = &H5A4D`
4. If it's correct, we proceed to add the value of `e_lfnew` to the base address; this is a relative address that tells us where the `IMAGE_NT_HEADERS` data is.
5. Since the optional header differs between bitnesses and we don't need it, we copy only the `Signature` and `IMAGE_FILE_HEADER`
6. The `Machine` member of the `IMAGE_FILE_HEADER` tells us what we want to know:

   ```vb6
   IMAGE_FILE_MACHINE_I386  = &H014c  ' Intel 386.
   IMAGE_FILE_MACHINE_AMD64  = &H8664&  ' AMD64 (K8)
   IMAGE_FILE_MACHINE_IA64  = &H0200  ' Intel 64
   IMAGE_FILE_MACHINE_ARM64  = &HAA64&  ' ARM64 Little-Endian
   ```
   Those are the ones we're interested in; there's many others, but they're either not supported on Windows at all, or were only on very old limited release or unreleased versions. The program will provide the raw value if it's not one of the above.

   The core function:

   ```vb6
       Private Function GetPEMachine(sFile As String) As Integer
        Dim lpBaseAddress As LongPtr
        Dim hFile As LongPtr
        Dim hMapping As LongPtr
    
        hFile = CreateFileW(StrPtr(sFile), GENERIC_READ, FILE_SHARE_READ, vbNullPtr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)

        If hFile = INVALID_HANDLE_VALUE Then
            AppendLog "Failed to open file " & sFile
            Return -1
        End If

        hMapping = CreateFileMappingW(hFile, vbNullPtr, PAGE_READONLY, 0, 0, 0)

        If hMapping = 0 Then
            AppendLog "Failed to map file " & sFile
            CloseHandle hFile
            Return -1
        End If

        lpBaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)
    
        If lpBaseAddress = 0 Then
            AppendLog "Failed to map file " & sFile
            CloseHandle hMapping
            CloseHandle hFile
            Return -1
        End If
        Dim tDOS As IMAGE_DOS_HEADER
        Dim tNT As IMAGE_NT_HEADERS
    
        'All EXEs and DLLs start with an IMAGE_DOS_HEADER structure
        CopyMemory tDOS, ByVal lpBaseAddress, LenB(tDOS)
        If tDOS.e_magic = IMAGE_DOS_SIGNATURE Then 'The magic number, 'MZ', is a good sign our address gave us a valid executable
            'e_lfanew points to the IMAGE_NT_HEADERS structure
            'We only copy the Signature and IMAGE_FILE_HEADER, because the optional header is different depending
            'on x86 or x64, and we don't it for this purpose.
            CopyMemory tNT, ByVal PointerAdd(lpBaseAddress, tDOS.e_lfanew), LenB(tNT.FileHeader) + 4
            UnmapViewOfFile lpBaseAddress
            CloseHandle hMapping
            CloseHandle hFile
            Return tNT.FileHeader.Machine
        Else
            AppendLog "Signature check failed, not a valid executable."
        End If
        UnmapViewOfFile lpBaseAddress
        CloseHandle hMapping
        CloseHandle hFile
        Return -1
    End Function
   ```

   I discovered something interesting while testing. While native Windows ARM64 executables have the ARM64 signature here, they don't appear to have it in memory when loaded for execution. The machine is AMD64 and you have to check a flag much deeper into the headers to tell them apart.

   That's about it, I hope you enjoyed this little foray into EXE/DLL internal structure!
   
