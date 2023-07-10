
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Test-vlBlockedProgram {
   <#
    .SYNOPSIS
        Tests if a program is blocked by the system.
    .DESCRIPTION
        Tests if a program is blocked by the system.
    .OUTPUTS
        A [bool] indicating if the program is blocked or not
    .EXAMPLE
        Test-vlBlockedProgram
    #>

   Param(
      [string]$ProgramPath
   )

   $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
   $processStartInfo.FileName = $ProgramPath
   $processStartInfo.RedirectStandardError = $true
   $processStartInfo.RedirectStandardOutput = $true
   $processStartInfo.UseShellExecute = $false
   $processStartInfo.CreateNoWindow = $true

   $process = New-Object System.Diagnostics.Process
   $process.StartInfo = $processStartInfo

   try {
      $process.Start() | Out-Null
      $process.WaitForExit()

      $exitCode = $process.ExitCode

      if ($exitCode -ne 0) {
         # the program is blocked
         return $true
      }
      else {
         # the program is not blocked
         return $false
      }
   }
   catch {
      # an exception occurred, indicating the program is blocked
      return $true
   }
}

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

      # check if bitlocker is enabled using Get-BitLockerVolume
      $bitlockerEnabled = Get-BitLockerVolume | Select-Object -Property  MountPoint, ProtectionStatus, EncryptionMethod, EncryptionPercentage, VolumeType
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

         if ($item.ProtectionStatus -ne "On" -or $item.EncryptionPercentage -ne 100) {
            $allEncrypted = $false
         }

         if ($item.VolumeType -eq "OperatingSystem" -and $item.ProtectionStatus -eq "On" -and $item.EncryptionPercentage -eq 100) {
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
   catch {
      if ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
         return New-vlErrorObject -message "Status could not be determined because Bitlocker was not set up for this system." -errorCode 1 -context $_
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
        detected: true if detected, false if not
    .EXAMPLE
        Get-COMHijacking
    #>
   try {

      $riskScore = 80
      $expectedValue = "$($env:SystemRoot)\system32\mmc.exe ""%1"" %*"

      $value = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Classes\mscfile\shell\open\command"

      if (($value.ToLower()) -eq ($expectedValue.ToLower())) {
         $result = [PSCustomObject]@{
            Detected = $false
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Detected = $true
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
        detected: true if detected, false if not
    .EXAMPLE
        Get-vlTimeProviderHijacking
    #>

   try {
      $riskScore = 80
      $expectedValue = "$($env:SystemRoot)\system32\w32time.dll"

      $value = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Value "DllName"

      if (($value.ToLower()) -eq ($expectedValue.ToLower())) {
         $result = [PSCustomObject]@{
            Detected = $false
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Detected = $true
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
         Description  = "This test determines whether the 'mmc.exe' executable file is set as the default program for .msc (Microsoft Management Console) files."
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
         Description  = "This test verifies whether the 'w32time.dll' file is set as the default time provider in the Windows operating system. The w32time.dll file is a crucial component responsible for time synchronization and accuracy within the system. Accurate timekeeping is essential for various system functionalities, including security protocols, authentication processes, and event logging."
         Score        = $timeProviderHijacking.Score
         ResultData   = $timeProviderHijacking.Result
         RiskScore    = $timeProviderHijacking.RiskScore
         ErrorCode    = $timeProviderHijacking.ErrorCode
         ErrorMessage = $timeProviderHijacking.ErrorMessage
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

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)
