
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlDrives {

   $drives = Get-CimInstance -ClassName Win32_DiskDrive
   $driveList = @()

   foreach ($drive in $drives) {
      $partitions = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($drive.DeviceID)'} WHERE AssocClass = Win32_DiskDriveToDiskPartition"

      foreach ($partition in $partitions) {
         $logicalDisks = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass = Win32_LogicalDiskToPartition"

         foreach ($logicalDisk in $logicalDisks) {

            $driveObject = [PSCustomObject]@{
               Model       = $drive.Model
               MediaType   = $drive.MediaType
               DriveLetter = $logicalDisk.DeviceID
               Interface   = $drive.InterfaceType
            }

            $driveList += $driveObject
         }
      }
   }

   return $driveList
}

function Get-vlIsBitlockerInstalled {
   <#
    .SYNOPSIS
        Checks if Bitlocker is installed on the system.
    .DESCRIPTION
        Checks if Bitlocker is installed on the system.
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-vlIsBitlockerInstalled
    #>

   try {
      $isBitLockerVolumeAvailable = Get-vlIsCmdletAvailable "Get-BitLockerVolume"

      if ( $isBitLockerVolumeAvailable -eq $true ) {

         $installed = Get-BitLockerVolume -ErrorAction Stop

         if ($installed) {
            return $true
         }
         else {
            return $false
         }
      }
      else {
         return $false
      }
   }
   catch {
      return $false
   }
}

function Get-vlBitlockerEnabled {
   <#
    .SYNOPSIS
        Checks if Bitlocker is enabled and used on the system.
    .DESCRIPTION
        Checks if Bitlocker is enabled and used on the system.
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-vlBitlockerEnabled
    #>

   try {
      $riskScore = 80

      $bitlockerInstalled = Get-vlIsBitlockerInstalled

      if ($bitlockerInstalled -eq $true) {
         # check if bitlocker is enabled using Get-BitLockerVolume
         $bitlockerEnabled = Get-BitLockerVolume |
         Select-Object -Property MountPoint,
         @{Name = 'Status'; Expression = { $_.ProtectionStatus } },
         EncryptionMethod,
         EncryptionPercentage,
         VolumeType

         $drives = Get-vlDrives

         # add the properties of drive to the bitlocker object by MountPoint and DriveLetter
         foreach ($drive in $drives) {
            $bitlockerEnabled | Where-Object { $_.MountPoint -eq $drive.DriveLetter } | Add-Member -MemberType NoteProperty -Name Model -Value $drive.Model
            $bitlockerEnabled | Where-Object { $_.MountPoint -eq $drive.DriveLetter } | Add-Member -MemberType NoteProperty -Name MediaType -Value $drive.MediaType
            $bitlockerEnabled | Where-Object { $_.MountPoint -eq $drive.DriveLetter } | Add-Member -MemberType NoteProperty -Name Interface -Value $drive.Interface
         }

         if ($bitlockerEnabled) {
            $bitlockerEnabled = Convert-vlEnumToString $bitlockerEnabled
         }

         # Initialize variables
         $allEncrypted = $true
         $osEncrypted = $false

         foreach ($item in $bitlockerEnabled) {
            if ($item.Interface -eq "USB") {
               continue
            }

            if ($item.Status -ne "On" -or $item.EncryptionPercentage -ne 100) {
               $allEncrypted = $false
            }

            if ($item.VolumeType -eq "OperatingSystem" -and $item.Status -eq "On" -and $item.EncryptionPercentage -eq 100) {
               $osEncrypted = $true
            }
         }

         if ($allEncrypted) {
            $score = 10
         }
         elseif ($osEncrypted) {
            $score = 5
         }
         else {
            $score = 0
         }

         return New-vlResultObject -result $bitlockerEnabled -score $score -riskScore $riskScore
      }
      else {
         $isWindowsServer = Get-vlIsWindowsServer -ErrorAction Stop

         $bitlockerStatus = [PSCustomObject]@{
            Status = "Bitlocker is not installed on this system."
         }

         $score = 0

         if ($isWindowsServer -eq $true) {
            $score = 8
         }

         return New-vlResultObject -result $bitlockerStatus -score $score -riskScore $riskScore
      }
   }
   catch {
      if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
         return New-vlErrorObject -message "Status could not be determined because Bitlocker was not set up for this system." -errorCode 1 -context $null
      }
      else {
         return New-vlErrorObject -context $_
      }
   }

}

function Get-COMHijacking {
   <#
    .SYNOPSIS
        Checks if mmc.exe is set as the default program for .msc files
    .DESCRIPTION
        Checks if mmc.exe is set as the default program for .msc files
    .OUTPUTS
        PSCustomObject
        isDefault: true if default, false if not
    .EXAMPLE
        Get-COMHijacking
    #>
   try {

      $riskScore = 80
      $expectedValue = "$($env:SystemRoot)\system32\mmc.exe ""%1"" %*"

      $value = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Classes\mscfile\shell\open\command"

      if ($value -and ($value.ToLower()) -eq ($expectedValue.ToLower())) {
         $result = [PSCustomObject]@{
            isDefault = $true
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            isDefault = $false
         }
         return New-vlResultObject -result $result -score 0 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlTimeProviderHijacking {
   <#
    .SYNOPSIS
        Checks if w32time.dll is set as the defalut time provider
    .DESCRIPTION
        Checks if w32time.dll is set as the defalut time provider
    .OUTPUTS
        PSCustomObject
        isDefault: true if default, false if not
    .EXAMPLE
        Get-vlTimeProviderHijacking
    #>

   try {
      $riskScore = 80
      $expectedValue = "$($env:SystemRoot)\system32\w32time.dll"

      $value = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Value "DllName"

      if ($value -and ($value.ToLower()) -eq ($expectedValue.ToLower())) {
         $result = [PSCustomObject]@{
            isDefault = $true
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            isDefault = $false
         }
         return New-vlResultObject -result $result -score 0 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlWindowsPersistanceCheck {
   <#
    .SYNOPSIS
        Runs sfc /verifyonly and checks if CBS.log contains "corrupt" or "repaired"
    .DESCRIPTION
        Runs sfc /verifyonly and checks if CBS.log contains "corrupt" or "repaired"
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-vlWindowsPersistanceCheck
    #>

   try {
      $riskScore = 80
      $log_file = "$($env:SystemRoot)\Logs\CBS\CBS.log"

      #run sfc /verifyonly and wait for it to finish run it hidden
      #$sfc = Start-Process -FilePath "sfc.exe" -ArgumentList "/verifyonly" -Wait -WindowStyle Hidden

      $today = (Get-Date).ToString("yyyy-MM-dd")

      # Check whether the log file exists
      if (Test-Path $log_file) {
         # Read the log file line by line and filter the lines that start with today's date
         $todayEntries = Get-Content $log_file | Where-Object { $_.StartsWith($today) }

         # Extract the numbers of the SR entries
         $numbers = $todayEntries | Where-Object { $_ -match "\[SR\]" } | ForEach-Object { if ($_ -match "(\b0*[0-9]{1,8}\b)\s+\[SR\]") { $matches[1] } }

         # Find the smallest and the largest SR entry
         $smallest = $numbers | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
         $largest = $numbers | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

         # Filter the lines that are between the smallest and the largest SR entry
         $filteredEntries = $todayEntries | Where-Object {
            if ($_ -match "(\d{1,8})\s+\[SR\]") {
               $number = $matches[1]
               $number -ge $smallest -and $number -le $largest
            }
         }

         # Output the filtered lines
         $filteredEntries
      }
      else {
         # Throw error if the log file does not exist
         throw "Log file does not exist"
      }

      #read the log file and check if it contains "corrupt" or "repaired"
      $defect = Get-Content $log_file | Select-String -Pattern "(corrupt|repaired)"

      if ($defect) {
         $result = [PSCustomObject]@{
            Detected = $true
         }
         return New-vlResultObject -result $result -score 0 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Detected = $false
         }
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlCheckWindowsRecallStatusLM {
   <#
    .SYNOPSIS
        Checks if Windows Recall is enabled on the system.
    .DESCRIPTION
        Windows Recall is a feature for Copilot+ PCs that creates a timeline of user activity by taking snapshots of the desktop and processing them using AI.

        https://support.microsoft.com/en-us/windows/retrace-your-steps-with-recall-aa03f8a0-a78b-4b3e-b0a1-2eb8ac48701c
        https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis
    .OUTPUTS
         PSCustomObject
         enabled: true if enabled, false if not
    .EXAMPLE
         Get-vlCheckWindowsRecallStatusLM
    #>

   try {
      <#
         0  Enable saving Snapshots for Windows. (Default)
         1	Disable saving Snapshots for Windows
      #>
      $riskScore = 50

      if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI") {
         $value = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Value "DisableAIDataAnalysis"

         if ($null -eq $value -or $value -eq 0) {
            $result = [PSCustomObject]@{
               Enabled = $true
            }

            return New-vlResultObject -result $result -score 0 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               Enabled = $false
            }
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
      }

      if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\WindowsAI") {
         $value = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\WindowsAI" -Value "DisableAIDataAnalysis"

         if ($null -eq $value -or $value -eq 0) {
            $result = [PSCustomObject]@{
               Enabled = $true
            }

            return New-vlResultObject -result $result -score 0 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               Enabled = $false
            }
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
      }

      $result = [PSCustomObject]@{
         Enabled = $false
      }

      return New-vlResultObject -result $result -score 10 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-WindowsConfigurationCheck {
   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("WCBitlocker")) {
      $checkBitlockerEnabled = Get-vlBitlockerEnabled
      $Output += [PSCustomObject]@{
         Name         = "WCBitlocker"
         DisplayName  = "WindowsConfiguration Bitlocker"
         Description  = "This test verifies the status of BitLocker, a hard disk encryption feature in Windows operating systems that provides enhanced data protection by encrypting the contents of hard disks."
         Score        = $checkBitlockerEnabled.Score
         ResultData   = $checkBitlockerEnabled.Result
         RiskScore    = $checkBitlockerEnabled.RiskScore
         ErrorCode    = $checkBitlockerEnabled.ErrorCode
         ErrorMessage = $checkBitlockerEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCComHijacking")) {
      $COMHijacking = Get-COMHijacking
      $Output += [PSCustomObject]@{
         Name         = "WCComHijacking"
         DisplayName  = "WindowsConfiguration COM hijacking"
         Description  = "This test determines whether the mmc.exe executable file is set as the default program for .msc (Microsoft Management Console) files."
         Score        = $COMHijacking.Score
         ResultData   = $COMHijacking.Result
         RiskScore    = $COMHijacking.RiskScore
         ErrorCode    = $COMHijacking.ErrorCode
         ErrorMessage = $COMHijacking.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCTimeProvHijacking")) {
      $timeProviderHijacking = Get-vlTimeProviderHijacking
      $Output += [PSCustomObject]@{
         Name         = "WCTimeProvHijacking"
         DisplayName  = "WindowsConfiguration time provider hijacking"
         Description  = "This test verifies whether the w32time.dll file is set as the default time provider in the Windows operating system. The w32time.dll file is a crucial component responsible for time synchronization and accuracy within the system. Accurate timekeeping is essential for various system functionalities, including security protocols, authentication processes, and event logging."
         Score        = $timeProviderHijacking.Score
         ResultData   = $timeProviderHijacking.Result
         RiskScore    = $timeProviderHijacking.RiskScore
         ErrorCode    = $timeProviderHijacking.ErrorCode
         ErrorMessage = $timeProviderHijacking.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCLMRecallStatus")) {
      $checkWindowsRecallStatus = Get-vlCheckWindowsRecallStatusLM
      $Output += [PSCustomObject]@{
         Name         = "WCLMRecallStatus"
         DisplayName  = "WindowsConfiguration Recall status - Machine"
         Description  = "[Experimental] This test determines the status of Windows Recall, a feature introduced with Windows 11 24H2 that creates a timeline of user activity by capturing desktop screenshots. Attackers could potentially exploit the collected data by extracting sensitive information."
         Score        = $checkWindowsRecallStatus.Score
         ResultData   = $checkWindowsRecallStatus.Result
         RiskScore    = $checkWindowsRecallStatus.RiskScore
         ErrorCode    = $checkWindowsRecallStatus.ErrorCode
         ErrorMessage = $checkWindowsRecallStatus.ErrorMessage
      }
   }

   <#
    #TODO: Add a better logic to check for "corrupt" or "repaired" in CBS.log
    if ($params.Contains("all") -or $params.Contains("persistancecheck")) {
        $persistancecheck = Get-vlWindowsPersistanceCheck
        $Output += [PSCustomObject]@{
            Name         = "WindowsConfiguration - persistancecheck"
            Score        = $persistancecheck.Score
            ResultData   = $persistancecheck.Result
            RiskScore    = $persistancecheck.RiskScore
            ErrorCode    = $persistancecheck.ErrorCode
            ErrorMessage = $persistancecheck.ErrorMessage
        }
    }
    #>

   return $output
}

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


Write-Output (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAuIRfx4wnmn/TR
# KmmVaZuD0Oy0Phji0acMpUg+pijdzqCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
# CDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8G
# A1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAe
# Fw0xNjA2MjQyMDQ0MzBaFw0zMTA2MjQyMDQ0MzBaMHgxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENv
# cnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBD
# QSBSU0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCfgxNzqrDG
# bSHL24t6h3TQcdyOl3Ka5LuINLTdgAPGL0WkdJq/Hg9Q6p5tePOf+lEmqT2d0bKU
# Vz77OYkbkStW72fL5gvjDjmMxjX0jD3dJekBrBdCfVgWQNz51ShEHZVkMGE6ZPKX
# 13NMfXsjAm3zdetVPW+qLcSvvnSsXf5qtvzqXHnpD0OctVIFD+8+sbGP0EmtpuNC
# GVQ/8y8Ooct8/hP5IznaJRy4PgBKOm8yMDdkHseudQfYVdIYyQ6KvKNc8HwKp4WB
# wg6vj5lc02AlvINaaRwlE81y9eucgJvcLGfE3ckJmNVz68Qho+Uyjj4vUpjGYDdk
# jLJvSlRyGMwnh/rNdaJjIUy1PWT9K6abVa8mTGC0uVz+q0O9rdATZlAfC9KJpv/X
# gAbxwxECMzNhF/dWH44vO2jnFfF3VkopngPawismYTJboFblSSmNNqf1x1KiVgMg
# Lzh4gL32Bq5BNMuURb2bx4kYHwu6/6muakCZE93vUN8BuvIE1tAx3zQ4XldbyDge
# VtSsSKbt//m4wTvtwiS+RGCnd83VPZhZtEPqqmB9zcLlL/Hr9dQg1Zc0bl0EawUR
# 0tOSjAknRO1PNTFGfnQZBWLsiePqI3CY5NEv1IoTGEaTZeVYc9NMPSd6Ij/D+KNV
# t/nmh4LsRR7Fbjp8sU65q2j3m2PVkUG8qQIDAQABo4H7MIH4MA8GA1UdEwEB/wQF
# MAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUNplkwMAYIKwYBBQUH
# AQEEJDAiMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNVHSAE
# CjAIMAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwOwYDVR0fBDQwMjAwoC6g
# LIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0G
# A1UdDgQWBBRUwv4QlQCTzWr158DX2bJLuI8M4zAOBgNVHQ8BAf8EBAMCAYYwDQYJ
# KoZIhvcNAQELBQADggIBAPUPJodwr5miyvXWyfCNZj05gtOII9iCv49UhCe204MH
# 154niU2EjlTRIO5gQ9tXQjzHsJX2vszqoz2OTwbGK1mGf+tzG8rlQCbgPW/M9r1x
# xs19DiBAOdYF0q+UCL9/wlG3K7V7gyHwY9rlnOFpLnUdTsthHvWlM98CnRXZ7WmT
# V7pGRS6AvGW+5xI+3kf/kJwQrfZWsqTU+tb8LryXIbN2g9KR+gZQ0bGAKID+260P
# Z+34fdzZcFt6umi1s0pmF4/n8OdX3Wn+vF7h1YyfE7uVmhX7eSuF1W0+Z0duGwdc
# +1RFDxYRLhHDsLy1bhwzV5Qe/kI0Ro4xUE7bM1eV+jjk5hLbq1guRbfZIsr0WkdJ
# LCjoT4xCPGRo6eZDrBmRqccTgl/8cQo3t51Qezxd96JSgjXktefTCm9r/o35pNfV
# HUvnfWII+NnXrJlJ27WEQRQu9i5gl1NLmv7xiHp0up516eDap8nMLDt7TAp4z5T3
# NmC2gzyKVMtODWgqlBF1JhTqIDfM63kXdlV4cW3iSTgzN9vkbFnHI2LmvM4uVEv9
# XgMqyN0eS3FE0HU+MWJliymm7STheh2ENH+kF3y0rH0/NVjLw78a3Z9UVm1F5VPz
# iIorMaPKPlDRADTsJwjDZ8Zc6Gi/zy4WZbg8Zv87spWrmo2dzJTw7XhQf+xkR6Od
# MIIG8zCCBNugAwIBAgIQfYHMItEnwWprKIwmkVmsVDANBgkqhkiG9w0BAQsFADB4
# MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
# ETAPBgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wuY29tIENvZGUgU2lnbmlu
# ZyBJbnRlcm1lZGlhdGUgQ0EgUlNBIFIxMB4XDTIzMDMwNzIyNTIyNloXDTI2MDMw
# NjIyNTIyNlowfDELMAkGA1UEBhMCREUxHDAaBgNVBAgME05vcmRyaGVpbi1XZXN0
# ZmFsZW4xGTAXBgNVBAcMEE1vbmhlaW0gYW0gUmhlaW4xGTAXBgNVBAoMEHZhc3Qg
# bGltaXRzIEdtYkgxGTAXBgNVBAMMEHZhc3QgbGltaXRzIEdtYkgwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDmsmxRhHnZ47SQfWJmJje0vVjTVhDfA15d
# Q99NkNBuxZV4F+zSdMuCH+CT77aJIa6fbQQzQCs5Z2bfia82RXAKgC9SPALFAdLq
# 3OyQ8IICyivsVn4IkLzGuEJPETDHWfRAJmICajFqyxX6DXcuOmxIm3c/s3F413DO
# uBn+oTebJu1lk/Mp0L+pd1MYnY3rKEsv+FuXE6valQqJRrIlkQA7sC2ji6A4tsA8
# 9NxK7IQlGIh4P2sEBq9YVrXOpCoxuzGC9zDwE1et1BrcviHr2z9AEfOD5te7CAbZ
# CukDEri7zskt8pL5vT+Djdn+u5yo689L3QcFG4JVs0AIPmxt91l8UJDX/I2oKBz8
# 4KuZGLExHDYETtIiCjB0gKBOWl4kojgqewBe8cL0HNcuCxmfMTubepSTF3R3UOrv
# bcSP2W34eJ353EEuCZMmkgQnj+Cu+g7fY379ddWO24rS9gonoSrsoCK7iVlGPLjz
# whKRe6S2vpFpsoEPo9bhdP5w1aCf/TQZixffdQSB2gFgGivgXjZ60ld5XUOG5eyZ
# ow6vEzKq7Bqnipd7t8xgBq6jIQ0y2fFS8o656pZvf7fvZ7bMM47uBXN9812/R4mX
# Zw6kvsH2k5YKZh97i9oBa+XCSeFVecFT5JY9uRj3SutCj5JvxsX5z5FH4qVedwse
# PYM6LtsztwIDAQABo4IBczCCAW8wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRU
# wv4QlQCTzWr158DX2bJLuI8M4zBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKG
# PGh0dHA6Ly9jZXJ0LnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJT
# QS00MDk2LVIxLmNlcjBRBgNVHSAESjBIMAgGBmeBDAEEATA8BgwrBgEEAYKpMAED
# AwEwLDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9j
# cmxzLnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJTQS00MDk2LVIx
# LmNybDAdBgNVHQ4EFgQUH4wxTfruqchOioKCaULdd2n1d6AwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQA+C1FID5jlerfUMR3DnJAe3ngwe/3YaItK
# 40Ccvd2ZG7lwmpho0ITP5EcXvQnkfsL5pGrXT1iRXMYrDgTz6eqtfpyC99F+fUGj
# aLrlOJvtzl1KypxHDRCvZKs2Qc7pceyvDZb+Wb4VrthpOYYTVfI+HWIYLiMH4fKB
# pkxCGLDipaPXHEQ+DNPUs1J7GpVyrh6jyMtfYZSEHz9YACvlT0FHooj7QDIlAX/u
# 6988XxGO8N4LZaaWUcLBb+LlQwiskVg+FXUMTarv7MS/e8ZirVfiHGXtiV9texcf
# 0LepL2nKtbcUTXYLucaW/8G+v0lO1H++K0/ziwqCCdxADzNR3/NGDth9vnLl+UPN
# 4QXCJEaw37RnipOxudFJOMqFSvNvARWNlxHvwgk+dRI5RDLKKSWdCKrC1/svMuG4
# sj+PgtITa3nWNVb56FpB6TXPc04Jqj7aeGcS7IfDKcZKXknVW/ngvZxLuKhdyJrk
# aovWHDjJNX2YuS6mAaw5CJ/5QDnxVD78qn9Zq4uqEg6aEnS1+FPuo42P+78sMuys
# +sjER4hLMrLhXfvwEOOHeweV75IF7rm5zDmZFJv54tJP3vuvNF1opr9ccWzhO3BG
# ufTWS/qKYurtB8uEmbJCH8ltE56bquVL0YRfVwVSV7gyp355x3Ptgu+v8YPDuzn3
# ZJjydk0JATGCAz8wggM7AgEBMIGMMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVU
# ZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNV
# BAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBSU0EgUjEC
# EH2BzCLRJ8FqayiMJpFZrFQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgvIW8Woolaw/R
# Mc27fY9lZFNwQj+KUYLBwx0Yp+rhoiQwDQYJKoZIhvcNAQEBBQAEggIAMn3Clffa
# ZgC9qXSd+iEprxLGRgBjc8oVXjPRP7cPubamWhDfrzaWYIxTe0oY2WPQVdtIpXEE
# rZ4zjosJWy2je7xSs0qtM+Ngt9b7YvKSuhRsiSb+3Neyrg5hG3JLDcpXEXdBI3w3
# 6FuplwGgXxWt0ghJiW9es9Hp9pwoqVXSp4c4j2fyfCHCaJt/ktWqeAXTycYBjnTE
# 4sB/vqjjZL0t827681lL91QZNmBq3ugA8m4vLtDyuPD1qGl9Jkxox9sUjwxnZ2i/
# dOek92ZkQrBq5/eH8l+gWxhubh2+BqaEShhfHJMvYxCr7AhbE5z0GnJd28rklB2J
# Zm3SLG0t62d6j7JubuIPawCYAM9EZvTz3EM0OJFAm5V7HW3Zz0tUJGrLsCiShGad
# 1/w9vSe08qSxBFKNbkj7YU/OSxcGKBFamcxsNx2UOwllFTuZfBQysgko1DoKWHxg
# RSYxYnfx15K65s1TSShdc2OgsBn+x9Eh4aU0KlOKSBRBkqQTbLM2VTtaJyZcFsrB
# V1GGv85xKkw/mb2peqqT11O+MEWhxesUkKqXTVL7MzxdXLHhD4Lml72Bf2vlzF7o
# QauYHzR8F3UJRNbNtPpErsATFLcD13QB8XHu+JaGBc0x16lW04XRmPklH7dpCfXY
# Vt8vw3st5GY977bCmc29TFDzSQD0A0ehz/M=
# SIG # End signature block
