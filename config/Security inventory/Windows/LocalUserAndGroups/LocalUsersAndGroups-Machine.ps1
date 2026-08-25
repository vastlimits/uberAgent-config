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
      return New-vlErrorObject -context $_
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
      $lapsLog = @()

      if ($eventLog.Warnings) {
         $lapsLog += $eventLog.Warnings
      }

      if ($eventLog.Errors) {
         $lapsLog += $eventLog.Errors
      }

      if ($eventLog.Errors.Count -gt 0) {
         return New-vlResultObject -result $lapsLog -score 8 -riskScore $riskScore
      }
      elseif ($eventLog.Warnings.Count -gt 0) {
         return New-vlResultObject -result $lapsLog -score 9 -riskScore $riskScore
      }

      return New-vlResultObject -result $lapsLog -score 10 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
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
      return New-vlErrorObject-context $_
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
      if ($availableFactors -and $availableFactors -band $factor.value) {
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
      return New-vlErrorObject -context $_
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
         Description  = "This test verifies that the Local Administrator Password Solution (LAPS) is set up and enabled. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
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
            Description  = "This test scans the event log for any Local Administrator Password Solution (LAPS) related errors and warnings. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
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

# SIG # Begin signature block
# MIIoxwYJKoZIhvcNAQcCoIIouDCCKLQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALDKZkoN46VolD
# HtgBggvrT+gk685ZSbi26raWYYp/E6CCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxghpkMIIaYAIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggb4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEqbz7aIa5VXLgm/eNv+xnpjb0CcLwj9
# pz1iuPudtW1SMFIGCisGAQQBgjcCAQwxRDBCoECAPgBMAG8AYwBhAGwAVQBzAGUA
# cgBzAEEAbgBkAEcAcgBvAHUAcABzAC0ATQBhAGMAaABpAG4AZQAuAHAAcwAxMA0G
# CSqGSIb3DQEBAQUABIIBgDHWr5o/h+ZsCaZnRKbLLyJmYiST1BKaLAAM8YSZFr1y
# rQ/XDpKvU5t0mUVJ9ZaAOqQKhIOvkQ+NJlzEeCEIayBD/AkXOGn/fXRqeDk/cy6V
# nr0kgsmnLsl0esJMd67539TBs2JX9v+6eIbanC/Z/hkB12cxiKFMJRLNjfNLlhAu
# EOJSKLsTmRjhcgbL+PN93GZRIPr5ngUBmtb+NHaUkeJ3v0hXsMJBcjV5yygXHLA9
# T3KsAOwA2Ud95szwxhTK5GQElEwm4d7fjmmv+2YLdLLXfZbRmKpAJShlSJFi9r3I
# XaedcmQmxP3FEeg64I0I77Ox08CwrGN/7SKsBKBsRBNuyrfro10gfwmvM/LLFu3c
# 26suHp+EX//SjGngX+n9ilLVl0zxZs3YUz5xkkoQ6MSxKE/027o6o+AzhhuJodoW
# /pZfUeaO6qtTGKwTRWYykN2rao5CM0jyAWz7kDbuxqYO6oXBAqBwRNce3FIR80fD
# RPX2+Qs8Q98EQNaAyZkyyqGCF3cwghdzBgorBgEEAYI3AwMBMYIXYzCCF18GCSqG
# SIb3DQEHAqCCF1AwghdMAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQ
# AQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBmveEATLv2
# wW7vEwy/8UJPUyzMcEjdjLdpKOhWmYxeHwIRANjlBRlEe1OKL9eKp6+50qcYDzIw
# MjYwODI1MDc0MTM5WqCCEzowggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRo
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBp
# bmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYw
# OTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBS
# ZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3Bs
# fAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71E
# m3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRw
# JXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJ
# E5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZ
# gPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jp
# hx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A7
# 7p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeW
# rzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoR
# on4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEh
# zZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwG
# A1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1Ud
# IwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1w
# aW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEI
# RJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLST
# wVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62
# PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZT
# TOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLace
# Rf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5
# GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGG
# hLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uu
# hqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FV
# F3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um
# 1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq
# 90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJ
# hjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdp
# Q2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1
# OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# tHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkb
# sDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+
# AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAkt
# VJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3
# Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv8
# 2wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638Z
# xqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7V
# vwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2N
# L+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTK
# IsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUoz
# ZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQw
# QwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N
# 0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7J
# d2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1j
# EMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdog
# P8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMv
# NYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBld
# NE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjT
# Y6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/B
# dHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyI
# PbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8
# dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2j
# NrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZI
# hvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNz
# dXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVow
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjww
# IjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J5
# 8soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMH
# hOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6
# Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQ
# ecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4b
# A3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9
# WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCU
# tNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvo
# ZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/J
# vNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCP
# orF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMB
# Af8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXr
# oq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRt
# MGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEF
# BQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgw
# BgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cH
# vZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8
# UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTn
# f+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxU
# jG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8j
# LfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDGCA3ww
# ggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0
# MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQME
# AgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkF
# MQ8XDTI2MDgyNTA3NDEzOVowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU3WIwrIYK
# LTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkEMSIEIK8aAliLlrpq37qJZUCi1b/4
# t4rErA9TyFjdapi+8Q+ZMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIEqgP6Is11yE
# xVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0GCSqGSIb3DQEBAQUABIICACdJU8Zo
# q2XzDDbUQw63Yc2ajiAzSt6lzMs0HhB8+fS5z8ypKDtulh5NaZjp+ne4hvwwTxnX
# /UnOD7TnZ/OgkiUeL6poWrd5672zkiOXUmpnWunZlyYGnnKRNsRN/ZIm/Q3zy699
# peI51HfUoMf1fAnIEKXRXFLKO8B0MzYLVAz6a3lXafZBRF3NRxK38ht4/zJFszsz
# lmqYPg0mik91m37rM3s/C5WD8/0dLzSpSyDOUXIP3ddQ4tA7mQBdhY0IuGZ44AKQ
# EvGvYx6gpd6tThkHi7eGxipaUq+yCv1aPHw9Vlv/ZOW5t+omQ2/+7zQq6xeW7ymI
# AUnjSNoh2XQBRBOVpTkmBMKiLRKg+ONsSNO8C0fU3K6ruBBBY2AyZLC+wtrkOY/c
# vfgzZ62DS14xKoam/TXoDO8KTU13voz7tuipFvOkp7y5DkMvSVjnDVLCzG3qyMfK
# epoKfydDrcXoNwUBlU9e2Yr3nhaCW3aQHfN6hHKENMH18V/85xX/iCpkikSyR3tH
# Yay1EettDq3BO1mEZyFFjxkYmOhzdee7m+UuaNdjWP/2bBKYRdRosSu0zIniyyG7
# YWfIWRm/xUpnnR5gCb0a5Ur5qT0qkvImaNmsSK8TrY0zw8y34IGlMwaR6ZESC2RD
# J0q/cLAt8q/2LlKYELenOLLH0BATQHeSpy3N
# SIG # End signature block
