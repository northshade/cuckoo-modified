# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Table for all hook logging statements.

This table is not automatically generated at the moment, but kept up-to-date
by hand.

"""
table = [
    ("__process__", "__init__", ("",)),
    ("__thread__", "__init__", ("",)),
    ("NtDeleteFile", "filesystem", ("O", "FileName")),
    ("CreateDirectoryW", "filesystem", ("u", "DirectoryName")),
    ("CreateDirectoryExW", "filesystem", ("u", "DirectoryName")),
    ("RemoveDirectoryA", "filesystem", ("s", "DirectoryName")),
    ("RemoveDirectoryW", "filesystem", ("u", "DirectoryName")),
    ("FindFirstFileExA", "filesystem", ("s", "FileName")),
    ("FindFirstFileExW", "filesystem", ("u", "FileName")),
    ("DeleteFileA", "filesystem", ("s", "FileName")),
    ("DeleteFileW", "filesystem", ("u", "FileName")),
    ("UnhookWindowsHookEx", "hooking", ("p", "HookHandle")),
    ("LdrGetDllHandle", "system", ("oP", "FileName", "ModuleHandle")),
    ("ExitWindowsEx", "system", ("ll", "Flags", "Reason")),
    ("IsDebuggerPresent", "system", ("",)),
    ("LookupPrivilegeValueW", "system", ("uu", "SystemName", "PrivilegeName")),
    ("NtClose", "system", ("p", "Handle")),
    ("URLDownloadToFileW", "network", ("uu", "URL", "FileName")),
    ("InternetReadFile", "network", ("pB", "InternetHandle", "Buffer")),
    ("InternetWriteFile", "network", ("pB", "InternetHandle", "Buffer")),
    ("InternetCloseHandle", "network", ("p", "InternetHandle")),
    ("DnsQuery_A", "network", ("sil", "Name", "Type", "Options")),
    ("DnsQuery_UTF8", "network", ("sil", "Name", "Type", "Options")),
    ("DnsQuery_W", "network", ("uil", "Name", "Type", "Options")),
    ("getaddrinfo", "network", ("ss", "NodeName", "ServiceName")),
    ("GetAddrInfoW", "network", ("uu", "NodeName", "ServiceName")),
    ("NtTerminateProcess", "process", ("pl", "ProcessHandle", "ExitCode")),
    ("ExitProcess", "process", ("l", "ExitCode")),
    ("system", "process", ("s", "Command")),
    ("RegOpenKeyExA", "registry", ("psP", "Registry", "SubKey", "Handle")),
    ("RegOpenKeyExW", "registry", ("puP", "Registry", "SubKey", "Handle")),
    ("RegDeleteKeyA", "registry", ("ps", "Handle", "SubKey")),
    ("RegDeleteKeyW", "registry", ("pu", "Handle", "SubKey")),
    ("RegEnumKeyW", "registry", ("plu", "Handle", "Index", "Name")),
    ("RegDeleteValueA", "registry", ("ps", "Handle", "ValueName")),
    ("RegDeleteValueW", "registry", ("pu", "Handle", "ValueName")),
    ("RegCloseKey", "registry", ("p", "Handle")),
    ("NtRenameKey", "registry", ("po", "KeyHandle", "NewName")),
    ("NtEnumerateKey", "registry", ("pl", "KeyHandle", "Index")),
    ("NtDeleteKey", "registry", ("p", "KeyHandle")),
    ("NtDeleteValueKey", "registry", ("po", "KeyHandle", "ValueName")),
    ("NtLoadKey", "registry", ("OO", "TargetKey", "SourceFile")),
    ("NtSaveKey", "registry", ("pp", "KeyHandle", "FileHandle")),
    ("ControlService", "services", ("pl", "ServiceHandle", "ControlCode")),
    ("DeleteService", "services", ("p", "ServiceHandle")),
    ("NtDelayExecution", "system", ("ls", "Milliseconds", "Status")),
    ("NtDelayExecution", "system", ("l", "Milliseconds")),
    ("WSAStartup", "socket", ("p", "VersionRequested")),
    ("gethostbyname", "socket", ("s", "Name")),
    ("socket", "socket", ("lll", "af", "type", "protocol")),
    ("connect", "socket", ("p", "socket")),
    ("send", "socket", ("pb", "socket", "buffer")),
    ("sendto", "socket", ("pb", "socket", "buffer")),
    ("recv", "socket", ("pb", "socket", "buffer")),
    ("recvfrom", "socket", ("pb", "socket", "buffer")),
    ("accept", "socket", ("pp", "socket", "ClientSocket")),
    ("bind", "socket", ("psl", "socket", "ip", "port")),
    ("bind", "socket", ("p", "socket")),
    ("setsockopt", "socket", ("pllb", "socket", "level", "optname", "optval")),
    ("listen", "socket", ("p", "socket")),
    ("select", "socket", ("p", "socket")),
    ("ioctlsocket", "socket", ("pl", "socket", "command")),
    ("closesocket", "socket", ("p", "socket")),
    ("shutdown", "socket", ("pl", "socket", "how")),
    ("WSARecv", "socket", ("p", "socket")),
    ("WSARecvFrom", "socket", ("p", "socket")),
    ("WSASend", "socket", ("p", "Socket")),
    ("WSASendTo", "socket", ("p", "Socket")),
    ("WSASocketA", "socket", ("lll", "af", "type", "protocol")),
    ("WSASocketW", "socket", ("lll", "af", "type", "protocol")),
    ("ConnectEx", "socket", ("pB", "socket", "SendBuffer")),
    ("NtOpenMutant", "synchronization", ("PO", "Handle", "MutexName")),
    ("NtGetContextThread", "threading", ("p", "ThreadHandle")),
    ("NtSetContextThread", "threading", ("p", "ThreadHandle")),
    ("NtResumeThread", "threading", ("pL", "ThreadHandle", "SuspendCount")),
    ("NtTerminateThread", "threading", ("pl", "ThreadHandle", "ExitStatus")),
    ("ExitThread", "threading", ("l", "ExitCode")),
    ("FindWindowA", "windows", ("ss", "ClassName", "WindowName")),
    ("FindWindowW", "windows", ("uu", "ClassName", "WindowName")),
    ("FindWindowExA", "windows", ("ls", "ClassName", "WindowName")),
    ("FindWindowExA", "windows", ("ss", "ClassName", "WindowName")),
    ("FindWindowExW", "windows", ("lu", "ClassName", "WindowName")),
    ("FindWindowExW", "windows", ("uu", "ClassName", "WindowName")),
    ("NtCreateFile", "filesystem", ("PpOll", "FileHandle", "DesiredAccess", "FileName", "CreateDisposition", "ShareAccess")),
    ("NtOpenFile", "filesystem", ("PpOl", "FileHandle", "DesiredAccess", "FileName", "ShareAccess")),
    ("NtReadFile", "filesystem", ("pb", "FileHandle", "Buffer")),
    ("NtWriteFile", "filesystem", ("pb", "FileHandle", "Buffer")),
    ("NtDeviceIoControlFile", "filesystem", ("pbb", "FileHandle", "InputBuffer", "OutputBuffer")),
    ("NtQueryDirectoryFile", "filesystem", ("pbo", "FileHandle", "FileInformation", "FileName")),
    ("NtQueryInformationFile", "filesystem", ("pb", "FileHandle", "FileInformation")),
    ("NtSetInformationFile", "filesystem", ("pb", "FileHandle", "FileInformation")),
    ("NtOpenDirectoryObject", "filesystem", ("PlO", "DirectoryHandle", "DesiredAccess", "ObjectAttributes")),
    ("NtCreateDirectoryObject", "filesystem", ("PlO", "DirectoryHandle", "DesiredAccess", "ObjectAttributes")),
    ("MoveFileWithProgressW", "filesystem", ("uu", "ExistingFileName", "NewFileName")),
    ("CopyFileA", "filesystem", ("ss", "ExistingFileName", "NewFileName")),
    ("CopyFileW", "filesystem", ("uu", "ExistingFileName", "NewFileName")),
    ("CopyFileExW", "filesystem", ("uul", "ExistingFileName", "NewFileName", "CopyFlags")),
    ("SetWindowsHookExA", "system", ("lppl", "HookIdentifier", "ProcedureAddress", "ModuleAddress", "ThreadId")),
    ("SetWindowsHookExW", "system", ("lppl", "HookIdentifier", "ProcedureAddress", "ModuleAddress", "ThreadId")),
    ("LdrLoadDll", "system", ("loP", "Flags", "FileName", "BaseAddress")),
    ("LdrGetProcedureAddress", "system", ("pSlP", "ModuleHandle", "FunctionName", "Ordinal", "FunctionAddress")),
    ("DeviceIoControl", "device", ("plbb", "DeviceHandle", "IoControlCode", "InBuffer", "OutBuffer")),
    ("WriteConsoleA", "system", ("pS", "ConsoleHandle", "Buffer")),
    ("WriteConsoleW", "system", ("pU", "ConsoleHandle", "Buffer")),
    ("InternetOpenA", "network", ("spssp", "Agent", "AccessType", "ProxyName", "ProxyBypass", "Flags")),
    ("InternetOpenW", "network", ("upuup", "Agent", "AccessType", "ProxyName", "ProxyBypass", "Flags")),
    ("InternetConnectA", "network", ("pslsslp", "InternetHandle", "ServerName", "ServerPort", "Username", "Password", "Service", "Flags")),
    ("InternetConnectW", "network", ("puluulp", "InternetHandle", "ServerName", "ServerPort", "Username", "Password", "Service", "Flags")),
    ("InternetOpenUrlA", "network", ("psSp", "ConnectionHandle", "URL", "Headers", "Flags")),
    ("InternetOpenUrlW", "network", ("puUp", "ConnectionHandle", "URL", "Headers", "Flags")),
    ("HttpOpenRequestA", "network", ("psl", "InternetHandle", "Path", "Flags")),
    ("HttpOpenRequestW", "network", ("pul", "InternetHandle", "Path", "Flags")),
    ("HttpSendRequestA", "network", ("pSb", "RequestHandle", "Headers", "PostData")),
    ("HttpSendRequestW", "network", ("pUb", "RequestHandle", "Headers", "PostData")),
    ("NtCreateProcess", "process", ("PpO", "ProcessHandle", "DesiredAccess", "FileName")),
    ("NtCreateProcessEx", "process", ("PpO", "ProcessHandle", "DesiredAccess", "FileName")),
    ("NtCreateUserProcess", "process", ("PPppOOoo", "ProcessHandle", "ThreadHandle", "ProcessDesiredAccess", "ThreadDesiredAccess", "ProcessFileName", "ThreadName", "ImagePathName", "CommandLine")),
    ("NtOpenProcess", "process", ("ppp", "ProcessHandle", "DesiredAccess", "ProcessIdentifier")),
    ("NtOpenProcess", "process", ("PpP", "ProcessHandle", "DesiredAccess", "ProcessIdentifier")),
    ("NtCreateSection", "process", ("PpOp", "SectionHandle", "DesiredAccess", "ObjectAttributes", "FileHandle")),
    ("NtOpenSection", "process", ("PpO", "SectionHandle", "DesiredAccess", "ObjectAttributes")),
    ("CreateProcessInternalW", "process", ("uupllpp", "ApplicationName", "CommandLine", "CreationFlags", "ProcessId", "ThreadId", "ProcessHandle", "ThreadHandle")),
    ("ShellExecuteExW", "process", ("2ul", "FilePath", "Parameters", "Show")),
    ("NtAllocateVirtualMemory", "process", ("pPPp", "ProcessHandle", "BaseAddress", "RegionSize", "Protection")),
    ("NtReadVirtualMemory", "process", ("2pB", "ProcessHandle", "BaseAddress", "Buffer")),
    ("ReadProcessMemory", "process", ("ppB", "ProcessHandle", "BaseAddress", "Buffer")),
    ("NtWriteVirtualMemory", "process", ("2pB", "ProcessHandle", "BaseAddress", "Buffer")),
    ("WriteProcessMemory", "process", ("ppB", "ProcessHandle", "BaseAddress", "Buffer")),
    ("NtProtectVirtualMemory", "process", ("pPPpP", "ProcessHandle", "BaseAddress", "NumberOfBytesProtected", "NewAccessProtection", "OldAccessProtection")),
    ("VirtualProtectEx", "process", ("pppp", "ProcessHandle", "Address", "Size", "Protection")),
    ("NtFreeVirtualMemory", "process", ("pPPp", "ProcessHandle", "BaseAddress", "RegionSize", "FreeType")),
    ("VirtualFreeEx", "process", ("pppl", "ProcessHandle", "Address", "Size", "FreeType")),
    ("RegCreateKeyExA", "registry", ("psslP", "Registry", "SubKey", "Class", "Access", "Handle")),
    ("RegCreateKeyExW", "registry", ("puulP", "Registry", "SubKey", "Class", "Access", "Handle")),
    ("RegEnumKeyExA", "registry", ("plss", "Handle", "Index", "Name", "Class")),
    ("RegEnumKeyExW", "registry", ("pluu", "Handle", "Index", "Name", "Class")),
    ("RegEnumValueA", "registry", ("plsr", "Handle", "Index", "ValueName", "Data")),
    ("RegEnumValueA", "registry", ("plsLL", "Handle", "Index", "ValueName", "Type", "DataLength")),
    ("RegEnumValueW", "registry", ("pluR", "Handle", "Index", "ValueName", "Data")),
    ("RegEnumValueW", "registry", ("pluLL", "Handle", "Index", "ValueName", "Type", "DataLength")),
    ("RegSetValueExA", "registry", ("pslr", "Handle", "ValueName", "Type", "Buffer")),
    ("RegSetValueExA", "registry", ("psl", "Handle", "ValueName", "Type")),
    ("RegSetValueExW", "registry", ("pulR", "Handle", "ValueName", "Type", "Buffer")),
    ("RegSetValueExW", "registry", ("pul", "Handle", "ValueName", "Type")),
    ("RegQueryValueExA", "registry", ("psr", "Handle", "ValueName", "Data")),
    ("RegQueryValueExA", "registry", ("psLL", "Handle", "ValueName", "Type", "DataLength")),
    ("RegQueryValueExW", "registry", ("puR", "Handle", "ValueName", "Data")),
    ("RegQueryValueExW", "registry", ("puLL", "Handle", "ValueName", "Type", "DataLength")),
    ("RegQueryInfoKeyA", "registry", ("pS6L", "KeyHandle", "Class", "SubKeyCount", "MaxSubKeyLength", "MaxClassLength", "ValueCount", "MaxValueNameLength", "MaxValueLength")),
    ("RegQueryInfoKeyW", "registry", ("pU6L", "KeyHandle", "Class", "SubKeyCount", "MaxSubKeyLength", "MaxClassLength", "ValueCount", "MaxValueNameLength", "MaxValueLength")),
    ("NtCreateKey", "registry", ("PlOo", "KeyHandle", "DesiredAccess", "ObjectAttributes", "Class")),
    ("NtOpenKey", "registry", ("PlO", "KeyHandle", "DesiredAccess", "ObjectAttributes")),
    ("NtOpenKeyEx", "registry", ("PlO", "KeyHandle", "DesiredAccess", "ObjectAttributes")),
    ("NtReplaceKey", "registry", ("pOO", "KeyHandle", "NewHiveFileName", "BackupHiveFileName")),
    ("NtEnumerateValueKey", "registry", ("pll", "KeyHandle", "Index", "KeyValueInformationClass")),
    ("NtSetValueKey", "registry", ("polR", "KeyHandle", "ValueName", "Type", "Buffer")),
    ("NtSetValueKey", "registry", ("pol", "KeyHandle", "ValueName", "Type")),
    ("NtQueryValueKey", "registry", ("polR", "KeyHandle", "ValueName", "Type", "Information")),
    ("NtQueryValueKey", "registry", ("po", "KeyHandle", "ValueName")),
    ("NtQueryMultipleValueKey", "registry", ("poS", "KeyHandle", "ValueName", "ValueBuffer")),
    ("NtLoadKey2", "registry", ("OOl", "TargetKey", "SourceFile", "Flags")),
    ("NtLoadKeyEx", "registry", ("pOOl", "TrustClassKey", "TargetKey", "SourceFile", "Flags")),
    ("NtQueryKey", "registry", ("pSl", "KeyHandle", "KeyInformation", "KeyInformationClass")),
    ("NtSaveKeyEx", "registry", ("ppl", "KeyHandle", "FileHandle", "Format")),
    ("OpenSCManagerA", "services", ("ssl", "MachineName", "DatabaseName", "DesiredAccess")),
    ("OpenSCManagerW", "services", ("uul", "MachineName", "DatabaseName", "DesiredAccess")),
    ("CreateServiceA", "services", ("pss4l3s", "ServiceControlHandle", "ServiceName", "DisplayName", "DesiredAccess", "ServiceType", "StartType", "ErrorControl", "BinaryPathName", "ServiceStartName", "Password")),
    ("CreateServiceW", "services", ("puu4l3u", "ServiceControlHandle", "ServiceName", "DisplayName", "DesiredAccess", "ServiceType", "StartType", "ErrorControl", "BinaryPathName", "ServiceStartName", "Password")),
    ("OpenServiceA", "services", ("psl", "ServiceControlManager", "ServiceName", "DesiredAccess")),
    ("OpenServiceW", "services", ("pul", "ServiceControlManager", "ServiceName", "DesiredAccess")),
    ("StartServiceA", "services", ("pa", "ServiceHandle", "Arguments")),
    ("StartServiceW", "services", ("pA", "ServiceHandle", "Arguments")),
    ("TransmitFile", "socket", ("ppll", "socket", "FileHandle", "NumberOfBytesToWrite", "NumberOfBytesPerSend")),
    ("NtCreateMutant", "synchronization", ("POl", "Handle", "MutexName", "InitialOwner")),
    ("NtCreateNamedPipeFile", "synchronization", ("PpOl", "NamedPipeHandle", "DesiredAccess", "PipeName", "ShareAccess")),
    ("NtCreateThread", "threading", ("PpO", "ThreadHandle", "ProcessHandle", "ObjectAttributes")),
    ("NtOpenThread", "threading", ("PlO", "ThreadHandle", "DesiredAccess", "ObjectAttributes")),
    ("NtSuspendThread", "threading", ("pL", "ThreadHandle", "SuspendCount")),
    ("CreateThread", "threading", ("pplL", "StartRoutine", "Parameter", "CreationFlags", "ThreadId")),
    ("CreateRemoteThread", "threading", ("3plL", "ProcessHandle", "StartRoutine", "Parameter", "CreationFlags", "ThreadId")),
    ("RtlCreateUserThread", "threading", ("plppPl", "ProcessHandle", "CreateSuspended", "StartAddress", "StartParameter", "ThreadHandle", "ThreadIdentifier")),
    ("NtMapViewOfSection", "process", ("ppPp", "SectionHandle", "ProcessHandle", "BaseAddress", "SectionOffset")),
    ("GetSystemMetrics", "misc", ("l", "SystemMetricIndex")),
    ("GetCursorPos", "misc", ("ll", "x", "y")),
]
