#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlUACState {
   <#
    .SYNOPSIS
        Function that checks if the UAC is enabled.
    .DESCRIPTION
        Function that checks if the UAC is enabled.
        This check is using the registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the UAC is enabled, the script will return a vlResultObject with the UACEnabled property set to true.
        If the UAC is disabled, the script will return a vlResultObject with the UACEnabled property set to false.
    .EXAMPLE
        Get-vlUACState
    #>

   $riskScore = 60

   try {
      $uac = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Value "EnableLUA"
      if ($uac -eq 1) {
         $result = [PSCustomObject]@{
            UACEnabled = $true
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            UACEnabled = $false
         }

         return New-vlResultObject -result $result -score 4 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlLAPSEventLog {
   <#
    .SYNOPSIS
        Retrieves LAPS (Local Administrator Password Solution) event logs from the Microsoft-Windows-LAPS/Operational log.

    .DESCRIPTION
        This function searches for LAPS events in the Microsoft-Windows-LAPS/Operational event log. It retrieves events with level 2 (error) and 3 (warning) that occurred within the given time range.

    .LINK
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/windows-laps-troubleshooting-guidance

    .OUTPUTS
        Returns a custom object with two properties:
        - Errors: An array containing LAPS events with Event ID 2 (error).
        - Warnings: An array containing LAPS events with Event ID 3 (warning).

    .EXAMPLE
         #Retrieves LAPS events from the Microsoft-Windows-LAPS/Operational log that occurred within the last 24 hours.
        Get-vlLAPSEventLog -StartTime (Get-Date).AddHours(-24)
   #>

   [CmdletBinding()]
   param (
      [DateTime]$StartTime = (Get-Date).AddHours(-24),
      [DateTime]$EndTime = (Get-Date)
   )

   $errors = @()
   $warnings = @()

   try {
      # Define the log name (for LAPS)
      $logName = 'Microsoft-Windows-LAPS/Operational'

      # Search the Event Logs for each Event ID
      Get-WinEvent -LogName $logName | Where-Object { $_.Level -eq 2 -or $_.Level -eq 3 -and $_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime } | ForEach-Object {
         # only keep: TimeCreated, Id, Message
         $winEvent = [PSCustomObject]@{
            TimeCreated = Get-vlTimeString -time $_.TimeCreated
            Id          = $_.Id
            Message     = $_.Message
         }

         # add the event to the errors array if the event id is 2 (error)
         if ($_.Level -eq 2) {
            $errors += $winEvent
         }

         # add the event to the warnings array if the event id is 3 (warning)
         if ($_.Level -eq 3) {
            $warnings += $winEvent
         }
      }

      # filter $errors and $warnings for unique events. Only keep latest event for each event id
      $errors = $errors | Group-Object -Property Id | ForEach-Object { $_.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1 }
      $warnings = $warnings | Group-Object -Property Id | ForEach-Object { $_.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1 }

      $result = [PSCustomObject]@{
         Errors   = $errors
         Warnings = $warnings
      }

      return $result
   }
   catch {
      $result = [PSCustomObject]@{
         Errors   = $errors
         Warnings = $warnings
      }

      return $result
   }
}

function Get-vlLAPSSettings {
   <#
    .SYNOPSIS
        Function that returns the LAPS settings.
    .DESCRIPTION
        Function that returns the LAPS settings.
        This check is using the registry key HKLM:\Software\Policies\Microsoft Services\AdmPwd
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the LAPS is enabled, the script will return a vlResultObject with the following properties:
            LAPSEnabled
            LAPSAdminAccountName
            LAPSPasswordComplexity
            LAPSPasswordLength
            LAPSPasswordExpirationProtectionEnabled
        If the LAPS is disabled, the script will return a vlResultObject with the LAPSEnabled property set to false.
    .EXAMPLE
        Get-vlLAPSSettings
    #>

   $riskScore = 40

   try {
      $hkey = "Software\Policies\Microsoft Services\AdmPwd"
      $AdmPwdEnabled = Get-vlRegValue -Hive "HKLM" -Path $hkey -Value "AdmPwdEnabled"

      if ($null -ne $AdmPwdEnabled) {
         $eventLog = Get-vlLAPSEventLog

         $lapsAdminAccountName = Get-vlRegValue -Hive "HKLM" -Path $hkey "AdminAccountName"
         $lapsPasswordComplexity = Get-vlRegValue -Hive "HKLM" -Path $hkey "PasswordComplexity"
         $lapsPasswordLength = Get-vlRegValue -Hive "HKLM" -Path $hkey "PasswordLength"
         $lapsExpirationProtectionEnabled = Get-vlRegValue -Hive "HKLM" -Path $hkey "PwdExpirationProtectionEnabled"

         $lapsSettings =
         [PSCustomObject]@{
            LAPSEnabled                             = $AdmPwdEnabled -eq 1
            LAPSAdminAccountName                    = $lapsAdminAccountName
            LAPSPasswordComplexity                  = $lapsPasswordComplexity
            LAPSPasswordLength                      = $lapsPasswordLength
            LAPSPasswordExpirationProtectionEnabled = $lapsExpirationProtectionEnabled -eq 1
            LAPSEventLog                            = $eventLog
         }

         if ($eventLog.Errors.Count -gt 0) {
            return New-vlResultObject -result $lapsSettings -score 8 -riskScore $riskScore
         }
         elseif ($eventLog.Warnings.Count -gt 0) {
            return New-vlResultObject -result $lapsSettings -score 9 -riskScore $riskScore
         }

         return New-vlResultObject -result $lapsSettings -score 10 -riskScore $riskScore
      }
      else {
         $lapsSettings =
         [PSCustomObject]@{
            LAPSEnabled = $false
         }
         return New-vlResultObject -result $lapsSettings -score 6 -riskScore $riskScore
      }

   }
   catch {
      return New-vlErrorObject($_)
   }
}

[Flags()] enum WinBioStatus {
   MULTIPLE = 0x00000001;
   FACIAL_FEATURES = 0x00000002;
   VOICE = 0x00000004;
   FINGERPRINT = 0x00000008;
   IRIS = 0x00000010;
   RETINA = 0x00000020;
   HAND_GEOMETRY = 0x00000040;
   SIGNATURE_DYNAMICS = 0x00000080;
   KEYSTROKE_DYNAMICS = 0x00000100;
   LIP_MOVEMENT = 0x00000200;
   THERMAL_FACE_IMAGE = 0x00000400;
   THERMAL_HAND_IMAGE = 0x00000800;
   GAIT = 0x00001000;
   SCENT = 0x00002000;
   DNA = 0x00004000;
   EAR_SHAPE = 0x00008000;
   FINGER_GEOMETRY = 0x00010000;
   PALM_PRINT = 0x00020000;
   VEIN_PATTERN = 0x00040000;
   FOOT_PRINT = 0x00080000;
   OTHER = 0x40000000;
   PASSWORD = 0x80000000;
}

function Get-vlMachineAvailableFactors () {
   <#
    .SYNOPSIS
        Function that returns the Machine Factors, that can be used.
    .DESCRIPTION
        Function that returns the Machine Factors, that can be used.
    .LINK
        https://uberagent.com
    .OUTPUTS
        Retruns if the Machine Factors are available and the name of the factors
    .NOTES
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo
    .EXAMPLE
        Get-vlMachineAvailableFactors
    #>

   $winBioUsed = $false
   $winBioAccountInfoPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo"
   $winBioSensorInfoBasePath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo"

   if (-not (Test-Path -Path ("HKLM:\" + $winBioSensorInfoBasePath ))) {
      return [PSCustomObject]@{
         WinBioAvailable        = $false
         WinBioUsed             = $false
         WinBioAvailableFactors = @()
      }
   }

   $bioUsers = Get-vlRegSubkeys -Hive "HKLM" -Path $winBioAccountInfoPath

   foreach ($bioUser in $bioUsers) {
      $bioUserValues = Get-vlRegValue -Hive "HKLM" -Path ($winBioAccountInfoPath + "\" + $bioUser.PSChildName) -Value "EnrolledFactors"

      if ($bioUserValues -and $bioUserValues -gt 0) {
         $winBioUsed = $true
      }
   }

   $availableFactors = Get-vlRegValue -Hive "HKLM" -Path $winBioSensorInfoBasePath -Value "AvailableFactors"

   # iterate over [WinBioStatus].GetEnumNames() and check if the bit is set. If bit is set, save matching enum names in array $availableFac
   $availableFac = @()
   foreach ($factor in [WinBioStatus].GetEnumNames()) {
      if ($availableFactors -band [WinBioStatus]::$factor) {
         $availableFac += $factor
      }
   }

   return [PSCustomObject]@{
      WinBioAvailable        = $true
      WinBioUsed             = $winBioUsed
      WinBioAvailableFactors = $availableFac
   }

}

function Get-vlWindowsHelloStatusLocalMachine () {
   <#
    .SYNOPSIS
        Function that checks if Windows Hello is enabled.
    .DESCRIPTION
        Function that checks if Windows Hello is enabled.
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the Windows Hello is enabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to true.
        If the Windows Hello is disabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to false.
    .EXAMPLE
        Get-vlWindowsHelloStatusLocalMachine
    #>

   $riskScore = 40

   try {
      $factors = Get-vlMachineAvailableFactors

      if ($factors.WinBioAvailable -and $factors.WinBioUsed) {
         return New-vlResultObject -result $factors -score 10 -riskScore $riskScore
      }
      else {
         return New-vlResultObject -result $factors -score 7 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlLocalUsersAndGroupsCheck {
   <#
    .SYNOPSIS
        Function that performs the LocalUsersAndGroups check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the LocalUsersAndGroups check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlLocalUsersAndGroupsCheck -uacState -lapsState -secrets
    #>

   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   if ($params.Contains("all") -or $params.Contains("LUMUac")) {
      $uac = Get-vlUACState
      $Output += [PSCustomObject]@{
         Name         = "LUMUac"
         DisplayName  = "User account control"
         Description  = "Checks if the User Account Control is enabled."
         Score        = $uac.Score
         ResultData   = $uac.Result
         RiskScore    = $uac.RiskScore
         ErrorCode    = $uac.ErrorCode
         ErrorMessage = $uac.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMLaps")) {
      $laps = Get-vlLAPSSettings
      $Output += [PSCustomObject]@{
         Name         = "LUMLaps"
         DisplayName  = "Local administrator password solution"
         Description  = "Checks if the Local Administrator Password Solution is enabled."
         Score        = $laps.Score
         ResultData   = $laps.Result
         RiskScore    = $laps.RiskScore
         ErrorCode    = $laps.ErrorCode
         ErrorMessage = $laps.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMWinBio")) {
      $windowsHelloStatus = Get-vlWindowsHelloStatusLocalMachine
      $Output += [PSCustomObject]@{
         Name         = "LUMWinBio"
         DisplayName  = "Windows Hello / biometrics"
         Description  = "Checks if Windows Hello is enabled and what factors are available."
         Score        = $windowsHelloStatus.Score
         ResultData   = $windowsHelloStatus.Result
         RiskScore    = $windowsHelloStatus.RiskScore
         ErrorCode    = $windowsHelloStatus.ErrorCode
         ErrorMessage = $windowsHelloStatus.ErrorMessage
      }
   }
   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlLocalUsersAndGroupsCheck | ConvertTo-Json -Compress)
