# =================================================
# Script: Collect-WindowsBinaryMeta.ps1
# Purpose: Get PE info, publisher, signature validity, and file hashes
# =================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$OutfilePath,      # Path to output CSV

    [Parameter(Mandatory=$true)]
    [ValidateSet("exe","dll","sys")]
    [string]$FileType          # Type of files to scan
)


$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true   

function check_output_path {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    $directory = Split-Path -Path $FilePath -Parent
    if (Test-Path -Path $directory -PathType Container) {
        # Ensure the output path ends with .csv
        if (-not $FilePath.ToLower().EndsWith(".csv")) {
            $FilePath += ".csv"
            }
        return $FilePath
    } else {
        Write-Host "The folder for the output file is not valid."
        exit
    }
}

function check_for_existing_outfile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    if (Test-Path -Path $FilePath) {
        Write-Host "The file '$FilePath' already exists."
        $response = Read-Host "Would you like to delete it? (y/n)"
        if ($response -eq 'y') {
            try {
        Remove-Item -Path $FilePath -Force
        Write-Host "File deleted successfully."
            }
            catch {
        Write-Host "Error deleting file: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "User chose not to delete the file. Exiting script."
            exit
        }
    }
}

function admin_perms_check {
    # Check if current session is elevated
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "Not running as Administrator. Relaunch with elevated privileges..."
        Pause
        exit
    }
}


# =================================================
# Get basic PE info
# =================================================
function get_pe_info {
    param(
        [string]$path,
        [PSCustomObject]$results
        )

    $bytes = [System.IO.File]::ReadAllBytes($path)

    # DOS header
    try {
        $dosSignature = [System.Text.Encoding]::ASCII.GetString($bytes[0..1])
        $results | Add-Member -NotePropertyName   "dosSignature"  -NotePropertyValue $dosSignature
    } catch {
        $results | Add-Member -NotePropertyName   "dosSignature"  -NotePropertyValue "-"
    }

    # PE offset (will be used to get the PE information)
    try {
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    } catch { 
        $results | Add-Member -NotePropertyName   "peSignature"  -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "machine"  -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "numberOfSections"  -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "entryPoint"  -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "imageBase"  -NotePropertyValue "-"
        return $results 
    }
    
    # PE header signature
    try {
        $peSignature = [System.Text.Encoding]::ASCII.GetString($bytes[$peOffset..($peOffset+3)])
        $results | Add-Member -NotePropertyName   "peSignature"  -NotePropertyValue $peSignature
    } catch {
        $results | Add-Member -NotePropertyName   "peSignature"  -NotePropertyValue "-"
    }

    # Machine type
    try {
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        $results | Add-Member -NotePropertyName   "machine"  -NotePropertyValue $machine
    } catch {
        $results | Add-Member -NotePropertyName   "machine"  -NotePropertyValue "-"
    }

    # Number of sections
    try {
        $numberOfSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
        $results | Add-Member -NotePropertyName   "numberOfSections"  -NotePropertyValue $numberOfSections
    } catch {
        $results | Add-Member -NotePropertyName   "numberOfSections"  -NotePropertyValue "-"
    }

    # EntryPoint
    try {
        $entryPoint = [BitConverter]::ToUInt32($bytes, $peOffset + 0x28)
        $results | Add-Member -NotePropertyName   "entryPoint"  -NotePropertyValue $entryPoint
    } catch {
        $results | Add-Member -NotePropertyName   "entryPoint"  -NotePropertyValue "-"
    }

    # Image base
    try {
        $imageBase = [BitConverter]::ToUInt32($bytes, $peOffset + 0x34)
        $results | Add-Member -NotePropertyName   "imageBase"  -NotePropertyValue $imageBase
    } catch {
        $results | Add-Member -NotePropertyName   "imageBase"  -NotePropertyValue "-"
    }

    return $results
}

# =================================================
# Get publisher info
# =================================================
function get_sig_info {
    param(
        [string]$path,
        [PSCustomObject]$results
        )

    $sig = Get-AuthenticodeSignature -FilePath $path

    if ( $null -eq $sig.SignerCertificate ) {
        # File is unsigned
        $results | Add-Member -NotePropertyName   "sigStatus"   -NotePropertyValue $sig.Status.ToString()
        $results | Add-Member -NotePropertyName   "sigStatusMessage"  -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "sigSubject"   -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "sigSubjectOrg"   -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "sigIssuer"    -NotePropertyValue "-"
        return $results
    } 
    try {
        $results | Add-Member -NotePropertyName   "sigStatus"  -NotePropertyValue $sig.Status.ToString()
    } catch {
        $results | Add-Member -NotePropertyName   "sigStatus"  -NotePropertyValue "-"
    }
    try {
        $results | Add-Member -NotePropertyName   "sigStatusMessage"  -NotePropertyValue $sig.StatusMessage.ToString()
    } catch {
        $results | Add-Member -NotePropertyName   "sigStatusMessage"  -NotePropertyValue "-"
    }
    try {
        $results | Add-Member -NotePropertyName   "sigSubject"   -NotePropertyValue $sig.SignerCertificate.Subject.ToString()
        if ($sig.SignerCertificate.Subject.ToString() -match " O=([^,]+)"){
            $results | Add-Member -NotePropertyName   "sigSubjectOrg"   -NotePropertyValue $matches[1]
        } else{
            $results | Add-Member -NotePropertyName   "sigSubjectOrg"   -NotePropertyValue "-"
        }
    } catch {
        $results | Add-Member -NotePropertyName   "sigSubject"   -NotePropertyValue "-"
        $results | Add-Member -NotePropertyName   "sigSubjectOrg"   -NotePropertyValue "-"
    }
    try {
        $results | Add-Member -NotePropertyName  "sigIssuer"    -NotePropertyValue $sig.SignerCertificate.Issuer.ToString()
    } catch {
        $results | Add-Member -NotePropertyName  "sigIssuer"    -NotePropertyValue "-"
    }
    return $results
}

# =================================================
# Compute file hashes (MD5, SHA1, SHA256)
# =================================================
function get_file_hashes {
    param(
        [string]$path,
        [PSCustomObject]$results
        )

    $hash = Get-FileHash -Algorithm MD5 -Path $path
    $results | Add-Member -NotePropertyName  "MD5" -NotePropertyValue $hash.Hash.ToString()
    $hash = Get-FileHash -Algorithm SHA1 -Path $path
    $results | Add-Member -NotePropertyName  "SHA1" -NotePropertyValue $hash.Hash.ToString()
    $hash = Get-FileHash -Algorithm SHA256 -Path $path
    $results | Add-Member -NotePropertyName  "SHA256" -NotePropertyValue $hash.Hash.ToString()
    
    return $results
}


admin_perms_check
$outfilePath = check_output_path -FilePath $OutfilePath
check_for_existing_outfile -FilePath $outfilePath

$seperator = "_" * $Host.UI.RawUI.WindowSize.Width

Get-ChildItem -Path "C:\" -Filter "*.$FileType"  -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object {
    $results = [PSCustomObject]@{
        fileName = $_.Name
        filePath = $_.FullName
        creationTime = $_.CreationTime
        lastWriteTime = $_.LastWriteTime
        fileVersion = $_.VersionInfo.FileVersion
    }
    Write-Host $seperator
    Write-Host $_.FullName
    $results = get_file_hashes -path  $_.FullName  -results $results
    $results = get_sig_info    -path  $_.FullName  -results $results
    $results = get_pe_info     -path  $_.FullName  -results $results
    $results | Export-Csv -Path $outfilePath -Append
    Remove-Variable results
    #Pause
}
Write-Host "`nDone"
