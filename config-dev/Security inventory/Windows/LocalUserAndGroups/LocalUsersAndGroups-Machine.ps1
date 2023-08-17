#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

$WinBioStatus = @{
   MULTIPLE           = 0x00000001
   FACIAL_FEATURES    = 0x00000002
   VOICE              = 0x00000004
   FINGERPRINT        = 0x00000008
   IRIS               = 0x00000010
   RETINA             = 0x00000020
   HAND_GEOMETRY      = 0x00000040
   SIGNATURE_DYNAMICS = 0x00000080
   KEYSTROKE_DYNAMICS = 0x00000100
   LIP_MOVEMENT       = 0x00000200
   THERMAL_FACE_IMAGE = 0x00000400
   THERMAL_HAND_IMAGE = 0x00000800
   GAIT               = 0x00001000
   SCENT              = 0x00002000
   DNA                = 0x00004000
   EAR_SHAPE          = 0x00008000
   FINGER_GEOMETRY    = 0x00010000
   PALM_PRINT         = 0x00020000
   VEIN_PATTERN       = 0x00040000
   FOOT_PRINT         = 0x00080000
   OTHER              = 0x40000000
   PASSWORD           = 0x80000000
}

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

      # Check if $Start time is before $End time if not swap them
      if ($StartTime -gt $EndTime) {
         $temp = $StartTime
         $StartTime = $EndTime
         $EndTime = $temp
      }

      try {
         # Search the Event Logs for each Event ID
         Get-WinEvent -LogName $logName -ErrorAction Stop | Where-Object { ($_.Level -eq 2 -or $_.Level -eq 3) -and $_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime } | ForEach-Object {
            # only keep: TimeCreated, Id, Message
            $winEvent = [PSCustomObject]@{
               TimeCreated = Get-vlTimeString -time $_.TimeCreated
               Id          = $_.Id
               Message     = $_.Message
               Level       = if ($_.Level -eq 2) { "Error" } elseif ($_.Level -eq 3) { "Warning" } else { "" }
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
      }
      catch {
         # if the log does not exist, return an empty result
         $result = [PSCustomObject]@{
            Errors   = $errors
            Warnings = $warnings
         }

         return $result
      }

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

function Get-vlLAPSTestEventLog {
   <#
    .SYNOPSIS
        Function that checks the Windows event log for LAPS errors and warnings.
    .DESCRIPTION
        Function that checks the Windows event log for LAPS errors and warnings.
    .OUTPUTS
        If the Windows event log contains LAPS errors, the script will return a vlResultObject with the EventLog errors and warnings.
    .EXAMPLE
        Get-vlLAPSTestEventLog
    #>
   try {
      $riskScore = 30
      $eventLog = Get-vlLAPSEventLog -StartTime (Get-Date).AddHours(-24) -EndTime (Get-Date)

      # merge lists to one output list
      $lapsLog = $eventLog.Warnings + $eventLog.Errors

      if ($eventLog.Errors.Count -gt 0) {
         return New-vlResultObject -result $lapsLog -score 8 -riskScore $riskScore
      }
      elseif ($eventLog.Warnings.Count -gt 0) {
         return New-vlResultObject -result $lapsLog -score 9 -riskScore $riskScore
      }

      return New-vlResultObject -result $lapsLog -score 10 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlLAPSSettings {
   <#
    .SYNOPSIS
        Function that returns the LAPS settings.
    .DESCRIPTION
        Function that returns the LAPS settings.
    .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings
    .OUTPUTS
        If the LAPS is enabled, the script will return a vlResultObject indicating the LAPS settings.
    .EXAMPLE
        Get-vlLAPSSettings
    #>

   $riskScore = 40

   try {
      <#
      https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings

      LAPS CSP	HKLM\Software\Microsoft\Policies\LAPS
      LAPS Group Policy	HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS
      LAPS Local Configuration	HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config
      Legacy Microsoft LAPS	HKLM\Software\Policies\Microsoft Services\AdmPwd

      Windows LAPS queries all known registry key policy roots, starting at the top and moving down.
      If no settings are found under a root, that root is skipped and the query proceeds to the next root.
      When a root that has at least one explicitly defined setting is found, that root is used as the active policy.
      If the chosen root is missing any settings, the settings are assigned their default values.
      #>

      $hkeys = @{
         'LAPS CSP'                 = 'Software\Microsoft\Policies\LAPS'
         'LAPS Group Policy'        = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
         'LAPS Local Configuration' = 'Software\Microsoft\Windows\CurrentVersion\LAPS\Config'
         'Legacy Microsoft LAPS'    = 'Software\Policies\Microsoft Services\AdmPwd'
      }

      $complexityArray = @(
         'A-Z',
         'A-Z + a-z',
         'A-Z + a-z + 0-9',
         'A-Z + a-z + 0-9 + special chars'
      )

      foreach ($hkey in $hkeys.GetEnumerator()) {

         # check if $hkey exists and contains any values
         $lapsRegSettings = Get-vlRegistryKeyValues -Hive "HKLM" -Path $hkey.Value

         if ($null -ne $lapsRegSettings -and $lapsRegSettings.PSObject.Properties.Count -ge 0) {
            $lapsSettings = [PSCustomObject]@{
               Mode               = $hkey.Key
               Enabled            = $true
               PasswordComplexity = if ( $lapsRegSettings.PSObject.Properties.Name -contains "PasswordComplexity" -and $lapsRegSettings.PasswordComplexity -ge 1 -and $lapsRegSettings.PasswordComplexity -le 4) { $complexityArray[$lapsRegSettings.PasswordComplexity - 1] } else { $null }
               PasswordLength     = if ( $lapsRegSettings.PSObject.Properties.Name -contains "PasswordLength") { $lapsRegSettings.PasswordLength } else { $null }
            }

            if ($hkey.Key -eq "Legacy Microsoft LAPS") {
               $lapsSettings.Enabled = if ( $lapsRegSettings.PSObject.Properties.Name -contains "AdmPwdEnabled") { $lapsRegSettings.AdmPwdEnabled -eq 1 } else { $false }

               if ($lapsSettings.Enabled -eq $true) {
                  return New-vlResultObject -result $lapsSettings -score 10 -riskScore $riskScore
               }
               else {
                  return New-vlResultObject -result $lapsSettings -score 6 -riskScore $riskScore
               }
            }

            return New-vlResultObject -result $lapsSettings -score 10 -riskScore $riskScore
         }
      }

      $lapsSettings =
      [PSCustomObject]@{
         Enabled = $false
      }
      return New-vlResultObject -result $lapsSettings -score 6 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject($_)
   }
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

   $availableFac = @()
   foreach ($factor in $WinBioStatus.GetEnumerator()) {
      if ($availableFactors -band $factor.value) {
         $availableFac += $factor.key
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
         Description  = "This test examines the status of User Account Control (UAC). User Account Control prevents unauthorized installation of new software, changes to system settings, or system files by requiring administrator-level privileges."
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
         DisplayName  = "Local administrator password solution - Settings"
         Description  = "This test verifies that the Local Administrator Password Solution (LAPS) is set up and enabled. The test scans the event log for any LAPS-related errors. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
         Score        = $laps.Score
         ResultData   = $laps.Result
         RiskScore    = $laps.RiskScore
         ErrorCode    = $laps.ErrorCode
         ErrorMessage = $laps.ErrorMessage
      }

      $lapsJSon = $laps.Result | ConvertFrom-Json

      if ( $lapsJSon.Enabled -eq $true -and ($params.Contains("all") -or $params.Contains("LUMLapsEventLog"))) {
         $lapsLog = Get-vlLAPSTestEventLog

         $Output += [PSCustomObject]@{
            Name         = "LUMLapsEventLog"
            DisplayName  = "Local administrator password solution - Event log"
            Description  = "This test scans the event log for any Local Administrator Password Solution (LAPS) related errors. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
            Score        = $lapsLog.Score
            ResultData   = $lapsLog.Result
            RiskScore    = $lapsLog.RiskScore
            ErrorCode    = $lapsLog.ErrorCode
            ErrorMessage = $lapsLog.ErrorMessage
         }
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMWinBio")) {
      $windowsHelloStatus = Get-vlWindowsHelloStatusLocalMachine
      $Output += [PSCustomObject]@{
         Name         = "LUMWinBio"
         DisplayName  = "Windows Hello/biometrics - Machine"
         Description  = "This test determines if Windows Hello is enabled and which factors are available. Windows Hello enables authentication using biometric factors such as fingerprint, facial or iris recognition additionally to PIN codes."
         Score        = $windowsHelloStatus.Score
         ResultData   = $windowsHelloStatus.Result
         RiskScore    = $windowsHelloStatus.RiskScore
         ErrorCode    = $windowsHelloStatus.ErrorCode
         ErrorMessage = $windowsHelloStatus.ErrorMessage
      }
   }
   return $output
}

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlLocalUsersAndGroupsCheck | ConvertTo-Json -Compress)
