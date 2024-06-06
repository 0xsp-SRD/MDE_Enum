# MDE_Enum

MDE_Enum is a comprehensive .NET tool designed to extract and display detailed information about Windows Defender exclusions and Attack Surface Reduction (ASR) rules. It is capable of querying both local and remote systems effectively, even from a low-user context, making it a versatile tool for system administrators and security professionals.

## Features
* **Local and Remote Query Support**: Seamlessly query Windows Defender settings on both local and remote machines.
* **User-Context**: Operates efficiently from a low-user context, eliminating the need for administrative permissions.
* **Windows Defender Exclusions**: Retrieve and list all exclusion paths configured in Windows Defender.
* **Attack Surface Reduction (ASR) Rules**: Enumerate ASR rules, displaying both the IDs and their corresponding names for easy identification.
* **Triggered ASR Events**: Extract and list all triggered ASR events to monitor system security activities.
* **Detailed Output**: Presents information in a clear, tabulated format for easy reading and analysis.


## Usage 

### Windows Defender exclusion paths

1. Enumerate exclusion paths locally 
```
MDE_Enum /local /paths 
```

2. Enumerate exclusion paths on remote computers
```
MDE_Enum <remoteComputer> <username> <password> <domain> /paths 
```

### Triggered ASR Rules 

1. Enumerate logged ASR rules locally 
```
MDE_Enum /local /asr 
```

2. Enumerate logged ASR rules on remote computers
```
MDE_Enum <remoteComputer> <username> <password> <domain> /asr 
```
### Enumerate ASR Rules 

1. Enumerate the rules locally 
```
MDE_Enum /local /asr /alt 
```
2. Enumerate the rules on remote computers. 
```
MDE_Enum <remoteComputer> <username> <domain> <password> /asr /alt 
```


