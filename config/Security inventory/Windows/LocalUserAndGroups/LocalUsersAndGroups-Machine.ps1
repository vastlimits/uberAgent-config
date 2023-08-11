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
            $eventLog = Get-vlLAPSEventLog -StartTime (Get-Date).AddHours(-24) -EndTime (Get-Date)

            $lapsSettings = [PSCustomObject]@{
               Mode               = $hkey.Key
               Enabled            = $true
               PasswordComplexity = if ( $lapsRegSettings.PSObject.Properties.Name -contains "PasswordComplexity" -and $lapsRegSettings.PasswordComplexity -ge 1 -and $lapsRegSettings.PasswordComplexity -le 4) { $complexityArray[$lapsRegSettings.PasswordComplexity - 1] } else { $null }
               PasswordLength     = if ( $lapsRegSettings.PSObject.Properties.Name -contains "PasswordLength") { $lapsRegSettings.PasswordLength } else { $null }
               EventLog           = $eventLog
            }

            if ($hkey.Key -eq "Legacy Microsoft LAPS") {
               $lapsSettings.Enabled = if ( $lapsRegSettings.PSObject.Properties.Name -contains "AdmPwdEnabled") { $lapsRegSettings.AdmPwdEnabled -eq 1 } else { $false }
            }

            if ($eventLog.Errors.Count -gt 0) {
               return New-vlResultObject -result $lapsSettings -score 8 -riskScore $riskScore
            }
            elseif ($eventLog.Warnings.Count -gt 0) {
               return New-vlResultObject -result $lapsSettings -score 9 -riskScore $riskScore
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
         DisplayName  = "Local administrator password solution"
         Description  = "This test verifies that the Local Administrator Password Solution (LAPS) is set up and enabled. The test scans the event log for any LAPS-related errors. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
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
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC9R+LD7nVLL5iP
# dUCsqAGp23FFBr2oVZMJ66AKlQ03b6CCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgJUHIqeQEjIEW
# 2/EVIoaQBV29zvKKb7rYEM2KFYz1tXUwDQYJKoZIhvcNAQEBBQAEggIAwJe5vbA5
# erAP6cXCIraH9p6tvFtM+92G1g37+IRllalFJgYVQniNRCyzRqENR0UzIDRrC1WC
# FjR3ZzlWyyPu7EuIUD8J8b1o+tBA0uhr9tGUgzSMKKY24Jz+QDxKwJkAaeSdPKPG
# WkEhi0vhgN+ueJccNR35O99RwgYAij8jIHZRHZbkgFQrRCZo+kaOFsOUeRJXXfI1
# aLacay5LL/zFMpQ4JZnMk0X6jjl9u5Lg8rM5j/7xlQWkC7llOsJTRkSKE3EwWqwC
# A9GMvuldLKh24Rj6nVsRHvHojMtqO1ed3aH1aXCZTN0kOcTdid6MRWXzTSQMSAfD
# ddwvhXeQg/k7lxo3+seqGyv0jDD0tcChAbfHawlg0UkL5RTOZY04VV7oSnvuLahC
# oy4zu3ubWX3ZkSGC2lxxsCFfZOK9LG1W030SEsuhLh+q6rzzie6ENIkcEV84EI24
# o1Kdl9Lq8HHQ9vsSywSssqsE45n6jWp6flpZzlZtelHgK7xKPElTRek8BL4lppKW
# tyblVXt4T+18t0og7/a8tWgBFD1eUcuRf03zUZ4Ei/uSHCfmK05MtS0c8wXoccBp
# Zmg00lKsD2lYfSzrFwA9f401FrGcU6REDzLvNARI2Zd8Y5tgX4uirsLVxFXyxaLF
# xbE4LyUnBTbrTfp+i/0qPmW2nZywzwtSbi0=
# SIG # End signature block
