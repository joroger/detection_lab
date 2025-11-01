# Windows Binary Meta Data Collection

This script was tested and run with pwsh.exe (PowerShell 7+). Older versions of PowerShell might not work. You can download PowerShell 7 [here](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5).

This PowerShell script will scan binary files, collect meta data, and save the results to a CSV file. Script must be run as administrator to ensure all files can be analyzed, not files will be modified. The script can scan either .exe, .dll, or .sys files.

To run the script use the following details:
```
pwsh.exe windows_bin_meta.ps1 -OutfilePath ".\your\path\out.csv" -FileType (exe, sys, or dll)
```
Examples:
```
pwsh.exe windows_bin_meta.ps1 -OutfilePath ".\your\path\out.csv" -FileType exe
```


The following information is saved to the CSV file.
 * fileName
 * filePath
 * creationTime
 * lastWriteTime
 * fileVersion
 * MD5
 * SHA1
 * SHA256
 * sigStatus
 * sigStatusMessage
 * sigSubject
 * sigSubjectOrg
 * sigIssuer
 * dosSignature
 * peSignature
 * machine
 * numberOfSections
 * entryPoint
 * imageBase


## Possible Usecases
 * Baselining a known list of "good" files.
 * Locating any invalid signed files due to corrupted or modification.
 * Using baseline data to filter out sysmon process creation logs. (Useful in a SIEM platform.)