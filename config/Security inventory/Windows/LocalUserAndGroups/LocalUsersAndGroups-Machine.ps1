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

   try {
      $uac = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Value "EnableLUA"
      if ($uac.EnableLUA -eq 1) {
         $result = [PSCustomObject]@{
            UACEnabled = $true
         }

         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            UACEnabled = $false
         }

         return New-vlResultObject -result $result -score 4
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlLAPSState {
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
        Get-vlLAPSState
    #>

   try {
      $laps = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value "AdmPwdEnabled"
      if ($laps.AdmPwdEnabled -eq 1) {
         $result = [PSCustomObject]@{
            LAPSEnabled = $true
         }

         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            LAPSEnabled = $false
         }

         return New-vlResultObject -result $result -score 6
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlSecrets {
   <#
    .SYNOPSIS
        Function that checks if LSA secrets are enabled.
    .DESCRIPTION
        Function that checks if LSA secrets are enabled.
        This check is using the registry key HKLM:\Security\Policy\Secrets
    .LINK
        https://uberagent.com
        https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
    .OUTPUTS
        If the LSA secrets are enabled, the script will return a vlResultObject with the SecretsEnabled property set to true.
        If the LSA secrets are disabled, the script will return a vlResultObject with the SecretsEnabled property set to false.
    .EXAMPLE
        Get-vlSecrets
    #>

   try {
      $AdmPwdEnabled = Get-vlRegValue -Hive "HKLM" -Path "Security\Policy\Secrets" -Value ""
      if ($AdmPwdEnabled) {
         $result = [PSCustomObject]@{
            SecretsEnabled = $true
         }
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            SecretsEnabled = $false
         }
         return New-vlResultObject -result $result -score 6
      }
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

   try {
      $hkey = "Software\Policies\Microsoft Services\AdmPwd"
      $AdmPwdEnabled = Get-vlRegValue -Hive "HKLM" -Path $hkey -Value "AdmPwdEnabled"

      if ($AdmPwdEnabled -ne "") {
         $lapsAdminAccountName = Get-RegValue -Hive "HKLM" -Path $hkey "AdminAccountName"
         $lapsPasswordComplexity = Get-RegValue -Hive "HKLM" -Path $hkey "PasswordComplexity"
         $lapsPasswordLength = Get-RegValue -Hive "HKLM" -Path $hkey "PasswordLength"
         $lapsExpirationProtectionEnabled = Get-RegValue -Hive "HKLM" -Path $hkey "PwdExpirationProtectionEnabled"

         $lapsSettings =
         [PSCustomObject]@{
            LAPSEnabled                             = $AdmPwdEnabled
            LAPSAdminAccountName                    = $lapsAdminAccountName
            LAPSPasswordComplexity                  = $lapsPasswordComplexity
            LAPSPasswordLength                      = $lapsPasswordLength
            LAPSPasswordExpirationProtectionEnabled = $lapsExpirationProtectionEnabled
         }
         return New-vlResultObject -result $lapsSettings -score 10
      }
      else {
         $lapsSettings =
         [PSCustomObject]@{
            LAPSEnabled = $false
         }
         return New-vlResultObject -result $lapsSettings -score 6
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

function Get-vlWindowsHelloStatusLocalUser () {
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
        Get-vlWindowsHelloStatusLocalUser
    #>

   try {
      $factors = Get-vlMachineAvailableFactors

      if ($factors.WinBioAvailable -and $factors.WinBioUsed) {
         return New-vlResultObject -result $factors -score 10
      }
      else {
         return New-vlResultObject -result $factors -score 7
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
         RiskScore    = 60
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
         RiskScore    = 40
         ErrorCode    = $laps.ErrorCode
         ErrorMessage = $laps.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMSecrets")) {
      $secrets = Get-vlSecrets
      $Output += [PSCustomObject]@{
         Name         = "LUMSecrets"
         DisplayName  = "Local security authority secrets"
         Description  = "Checks if LSA secrets are available."
         Score        = $secrets.Score
         ResultData   = $secrets.Result
         RiskScore    = 40
         ErrorCode    = $secrets.ErrorCode
         ErrorMessage = $secrets.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMWinBio")) {
      $windowsHelloStatus = Get-vlWindowsHelloStatusLocalUser
      $Output += [PSCustomObject]@{
         Name         = "LUMWinBio"
         DisplayName  = "Windows Hello / biometrics"
         Description  = "Checks if Windows Hello is enabled and what factors are available."
         Score        = $windowsHelloStatus.Score
         ResultData   = $windowsHelloStatus.Result
         RiskScore    = 40
         ErrorCode    = $windowsHelloStatus.ErrorCode
         ErrorMessage = $windowsHelloStatus.ErrorMessage
      }
   }
   return $output
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlLocalUsersAndGroupsCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIFyAYJKoZIhvcNAQcCoIIFuTCCBbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDizAOdpKLOSl9q
# eOGufpGznOLcxJ3osxNHitjMa9eY6KCCAywwggMoMIICEKADAgECAhAV/4qQJS3s
# n0DL41n50ym+MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNVBAMMIVRlc3QgUG93ZXJT
# aGVsbCBDb2RlIFNpZ25pbmcgQ2VydDAeFw0yMzA0MDYwOTA0MjNaFw0yODA0MDYw
# OTE0MjNaMCwxKjAoBgNVBAMMIVRlc3QgUG93ZXJTaGVsbCBDb2RlIFNpZ25pbmcg
# Q2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMY2H9hHui4rAfqN
# n3QDc37qHGDNZBB2g9yFELoJhgKIcvsoEOdjx+1ZqrlSet7j1gBAnOw2hvFmLdLr
# HL5t23Z4FnIBog1ictyCShaUZ4o6YKChLEofvkajnlN/WeEjDWYlmxp8Lp+u/kzc
# SZUUjx+s9IkrlfjDjPXipOzOLPaAzFa+pqqB4gD6czC80aA3h7mx6ot3TT9FMx6k
# 1XCgG2coWpdE+/XGhy99FBgHROskiwUrfO2AG6s2RpppUz2O6kf7ndMj/uDtvSpU
# shDSqMshoLyWnHl4TqarY7roiktIQFFONp3iJ1qKule67xS0xDBuJwhaf62QNKNN
# 67lWU/kCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMB0GA1UdDgQWBBRmSIOJwRja8evKIW1LiVBOivpyLTANBgkqhkiG9w0BAQsF
# AAOCAQEAYsHAnLyLgEj87rcgPuGWs51PdU5g9/b2AVdniV0MuljX9Mlw+nnddN6F
# a075DO1/L+dsJdYmxHw9Hp2OdNbqVZCNcI/s3wM+JVTXXkdroPWafJb2caw5V6p3
# p2g32zBdtInxUiL06S/oiUMZg9JK9xu+cTPgFPU2a0xpjx6exNCbYW8ByO8WrT2f
# z3Gh4nSJ9Da3k02F1E3V9jUno4s0fKuYoZDd1MlkNuK5D1A1fH8bsn2J5mR25OHv
# fBBGQIEzbYCXhDPIydtGDvBjj9e3OzMS/h5XcGD5FcyVOwI4/n0A7asKHTbD+JI9
# CT+XeyJVdPVtVbi029LXl5Ztw6SMNjGCAfIwggHuAgEBMEAwLDEqMCgGA1UEAwwh
# VGVzdCBQb3dlclNoZWxsIENvZGUgU2lnbmluZyBDZXJ0AhAV/4qQJS3sn0DL41n5
# 0ym+MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIg58yOCHnehDNtVjVtlTtCFq8Qp5qpw
# uIHpsj3OS3JdMA0GCSqGSIb3DQEBAQUABIIBAIfZdFuf+C0TLO4ncOAZxgJhRBH6
# QzvG8tYKteOuaFV3LrgHFlOMPRkvfbRrdrWd3tOsMTj1Jgv7L+F7t3DKs0sabJRy
# v2q5aKGzfnAvGMGoDwkdFRgi0/yed9x81/WqGAyKNXt0c3iQ52iJ3pIBhQt5kvRm
# dPaemJgxYN8m0Dwa1aPWN+PfZArSiAmA4k+HTF4kUQeFvS9r6IvTtmpCGY1alaqs
# pV9Gnb7H7WTHyDqoFJivU264jyXYrZi7wP4r7A07QSDVwDm6bmWgQl7Vhvkh875V
# Yy8E1vMx82XCi0rK1UdzNTJ9J+kAFSHV2FvgGF0pBNVlYGW2OyzKdB/PAVg=
# SIG # End signature block
