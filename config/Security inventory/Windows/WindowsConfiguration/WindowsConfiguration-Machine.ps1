
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
# MIIoyAYJKoZIhvcNAQcCoIIouTCCKLUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBWTDAiH1gM6Q7B
# 8hFXho2rCVcpMLUZID67qXJMwf0106CCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggcBMIIE6aADAgECAhAP47Ki0imEqa3MI1tkbzHeMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE0MDAwMDAwWhcNMjcwNTEz
# MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0Zsb3JpZGExGDAWBgNV
# BAcTD0ZvcnQgTGF1ZGVyZGFsZTEdMBsGA1UEChMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4xDzANBgNVBAsTBkNpdHJpeDEdMBsGA1UEAxMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDWvV/OH9/sYPfeiQAh
# eDNU6vKMQlp+6UDbpI629yfSkJFN8YHaKLwTBL7o8njOMKdbFOSC1LwWh04pGV0Z
# DoCwXTOmzvXm10J2D6a6FKt6mZSKpwzI9RHbU8r26rhU0YU3ikAVDjTwHj44QHeL
# 0znzOlAAxzglEvpCOjHmluKMmaGqFtMdshrC4JPHjSS3Ksy2CSt5zNV88eEoU51v
# MsV/mN7wwnS8pfvFX+1J0dbHxcizG8HAeP66DG9Sedi1Tzm9beBcgYR4IMLXEe6B
# ac2y1AhOc+qFAWhj7ayMy3Mhxk4EZbXVGDP3n+GjiBUnWEfFu3DSucBi6uID+d/r
# 1mkT00hADT/aC2eT/Q/DEm+zVEuOQduX0YmBSe3anfTVLcDieVw/pI60U/e/4L8p
# JDgDwDziLIFKogXRtQYnV9fn3PqMisEigo22HCU6ieJq2lkPb6AZhdSjgFEz242t
# uDwfstvbn6tiZUXa6HggVbPZVZXTUFKhBsC8WE7VdNVd2HECAwEAAaOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBRbcl4N
# sqHrugpyuVoA9I4eak86SjA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAba1In5WIqLU6LE1uLOVwCllMLOAVeWUb1wPJ2fugaH891Oy42VUvND/cxd2L
# Fl8aIBEn9snnxJpFlyoLG3eNZYPLvSHgFuWlBlHkp4cwL4hihgjXQvRdhKFINE87
# 7RCLg9aNh8LzxNs9ciMM/sho/+dv2cojZPBqCZBxL9Fk+irRkZNUwgtR6/F2ijMu
# BnbGI9M24J6QqGj81wOSIrldQ/6hFGhDG0h58VZ+s8W0Bl4gf6P7lxZb8t0biBD5
# uijZxf9Ny4grACnIY9YQQRAH9k4QcBofNvro4U20OQIjRP7i7acQ5+SyFBzIn5Ko
# MkspCGz8VkvefMDgj91dXJSBBZlWIPRkRRETTbZhq83zjZNeupLCDMGJg1hUvtOu
# Is+Wn3+1/K5jrBK9dW3BukExwO/HpumRJ5T3gCPeCz8015XXsvixZSJPW91U1zwt
# +srK0tvNKBIPGSaVfJkLsf5iKeTQVCZtR8Y17ZNX0rLU3DeBytc3d3jfafqeVlih
# YrCTmQp9FiL9gzlr4OxVghgP6mCki7B/0SJXGg+tR1AOp12T5h/FSelSoPgECFhn
# aWQct57F/q6gSrTxVxwm1/xjb2EehEriH0H+TSJ+Jhu+z4y/Slc3qzt3haC8GjEU
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxghplMIIaYQIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggcAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEILb9bAUnRHqUGWquKH/KmW0Mi9h48xHl
# aU4kg+ZK9ZzjMFQGCisGAQQBgjcCAQwxRjBEoEKAQABXAGkAbgBkAG8AdwBzAEMA
# bwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4ALQBNAGEAYwBoAGkAbgBlAC4AcABzADEw
# DQYJKoZIhvcNAQEBBQAEggGAtyD0i8ImJBwA8cAD9BHru28X1eI4If2onnGHy43g
# ytM/dWDF/3+zakIqzcsbkoVqozx9RPwaIg2eIyzGa4oW1+d4cxY6D6ZD/OXwroam
# dntkLe3cOK5fuQh6im+GNUH8GpGh8ZGLSbP5k9Jekfka1qd5D9rAH4eZYiIWVgw6
# 7UCvAcUIwXuAUeBrgvqlc9PR8EYn75ObJaQ2D38lpsDM2jId33y5IvHvQ68JlBaE
# CvX1R6ZIx8pdSyPoXkdV5mol5cTAQYEHqHDFZazcXI0MU+0JceYa0MbEr0vkdjfc
# BfbPpdkioq8Lx537+DTHgaHAuScKyIWeOOhqtle7TOEXb/reXYnVq53SAEd9Znkd
# nkWXyQlOhsk+STaSLjnQa3HWl9Ny1Kb9AhfEOnCu6O2CETKrz17NpNvjX3aRYGah
# WZ0VsFYp/HJMZiapYDJ07gXpjIybJLTuP40YRgs+VPGOt90carxWmjtUI8YV4Vtg
# 9U1iDpZFVPmWGSYNzkg+OAP+oYIXdjCCF3IGCisGAQQBgjcDAwExghdiMIIXXgYJ
# KoZIhvcNAQcCoIIXTzCCF0sCAQMxDzANBglghkgBZQMEAgEFADB3BgsqhkiG9w0B
# CRABBKBoBGYwZAIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIN/zwl4Z
# s6BWbyktDR/OlwQJSroCOTj7zw/8NhQdKCYBAhBWRe6EbFD9o382qjzRmKP+GA8y
# MDI2MDgyNTA3NDE1OFqgghM6MIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6
# SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGln
# aUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIz
# NTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5
# G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD
# /gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJ
# LVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CV
# NxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr
# /NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/
# GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe
# 1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8lad
# jS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052Ak
# yiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlK
# M2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0
# MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/
# zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+
# yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmd
# YxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6Rna
# ID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7j
# LzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZ
# XTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o
# 02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXf
# wXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHM
# iD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw
# /HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFt
# oza2zNaQ9k+5t1wwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqG
# SIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFz
# c3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTla
# MGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9v
# dCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8
# MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauy
# efLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34Lz
# B4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+x
# embud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhA
# kHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1Lyu
# GwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2
# PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37A
# lLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD7
# 6GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/
# ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXA
# j6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTAD
# AQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF
# 66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEE
# bTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYB
# BQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979X
# B72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4k
# vFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU
# 53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pc
# VIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5v
# Iy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQxggN8
# MIIDeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUD
# BAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA4MjUwNzQxNThaMCsGCyqGSIb3DQEJEAIMMRwwGjAYMBYEFN1iMKyG
# Ci0wa9o4sWh5UjAH+0F+MC8GCSqGSIb3DQEJBDEiBCDqtUHN0ylYuH6H8IUIthfX
# ZvbG+urAx792m5xpnLrEJDA3BgsqhkiG9w0BCRACLzEoMCYwJDAiBCBKoD+iLNdc
# hMVck4+CjmdrnK7Ksz/jbSaaozTxRhEKMzANBgkqhkiG9w0BAQEFAASCAgAKPmoy
# 6w5egFFJOrmIpi6pRDuNHBqg/Z6hOwMkIkYIqcTI2shluW9pITGNMTXMMqKT4Ytv
# bgam6O37jhV/SnLLGhWHvLpWlfxOltN7E/kVVlxeCbwigS4AmcN0ailgug5U5Tuo
# RqmzFNJ+ycfQ8SquovJaphD8bm6DX3Fs/Qhsr5ROzifDOSbfat5BVar4VvJ25qDI
# ymUH/6Vr9xkLTJBTvxkeupvQO0pnIMPudDUMf6E4IBEDiPk71CHayMFvfFmxcJ9l
# b9eyn7BgK2UIanG0T5D+/Brtc0qPzlpC2zCos5JvxmGz95WkVLJ4xwUV9UFbbTvY
# GzHtWzL3yvCEc2sVrE52c6vvEryWfkw3u2TyJugyuN1I4h9c7uOLaezWM+gNFxER
# QevMgjRNyIqh3JjU33WVZM8HGbaIkypB7NOI0OAxl0QnchON+HXxINDDt+hDHequ
# JSa/wrp5+ttgLaFski3hveLICQPvt6rTSn6uj7N6Zjz0Sp8jh08HaVm+i+pCbZNV
# u07GhZzxO1pDcjYMOxmQ/6OgDzldUpip+jfLqk2fyEszX/9nHTGoS/DATpfEjglJ
# f055ibkAT4SKt5FLGkjAX/3gMO+hKvsrDhA0F4hZCEzkyU/GH7qUCT0IkKpRJq7i
# HfHIMRmtv+Zw7I0F8ii0wTkISEPSkOIZjxBApQ==
# SIG # End signature block
