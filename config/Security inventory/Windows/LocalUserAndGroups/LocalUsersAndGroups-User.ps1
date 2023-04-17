#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

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

function Get-vlIsLocalAdmin {
   <#
    .SYNOPSIS
        Function that checks if the user is a local admin.
    .DESCRIPTION
        Function that checks if the user is a local admin.
    .LINK
        https://uberagent.com

    .OUTPUTS
        If the user is a local admin, the script will return a vlResultObject with the IsLocalAdmin property set to true.
        If the user is not a local admin, the script will return a vlResultObject with the IsLocalAdmin property set to false.

    .EXAMPLE
        Get-vlIsLocalAdmin
    #>

   try {
      #checks if use has claim object S-1-5-32-544 (local admin group)
      $isLocalAdmin = [Security.Principal.WindowsIdentity]::GetCurrent().Claims.Value.Contains('S-1-5-32-544')
      if ($isLocalAdmin) {
         $result = [PSCustomObject]@{
            IsLocalAdmin = $true
         }

         return New-vlResultObject -result $result -score 3
      }
      else {
         $result = [PSCustomObject]@{
            IsLocalAdmin = $false
         }
         return New-vlResultObject -result $result -score 10
      }
   }
   catch {
      return New-vlErrorObject($result)
   }
}


function Get-vlGetUserEnrolledFactors() {
   <#
    .SYNOPSIS
        Function that returns the user's enrolled bio factors.
    .DESCRIPTION
        Function that returns the user's enrolled bio factors.
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the Windows Hello is enabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to true.
        If the Windows Hello is disabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to false.
    .NOTES
        https://learn.microsoft.com/en-us/windows/win32/api/winbio/nf-winbio-winbiogetenrolledfactors
        WinBioGetEnrolledFactors

        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\S-1-12-1-*
    .EXAMPLE
        Get-vlGetUserEnrolledFactors
    #>

   $winBioBasePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio"

   if (-not (Test-Path -Path $winBioBasePath)) {
      return [PSCustomObject]@{
         WinBioAvailable = $false
         WinBioUsed      = $false
      }
   }

   $currentUserSID = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).value

   if (-not (Test-Path -Path ($winBioBasePath + "\AccountInfo\" + $currentUserSID))) {
      return [PSCustomObject]@{
         WinBioAvailable = $true
         WinBioUsed      = $false
      }
   }

   $enroledFactors = Get-vlRegValue -Hive "HKLM" -Path ("SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\" + $currentUserSID) -Value "EnrolledFactors"

   # iterate over [WinBioStatus].GetEnumNames() and check if the bit is set. If bit is set, save matching enum names in array $enroleFactors
   $enroledFac = @()
   foreach ($factor in [WinBioStatus].GetEnumNames()) {
      if ($enroledFactors -band [WinBioStatus]::$factor) {
         $enroledFac += $factor
      }
   }

   return [PSCustomObject]@{
      WinBioAvailable      = $true
      WinBioUsed           = $true
      WinBioEnroledFactors = $enroledFac
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
    .NOTES
        https://learn.microsoft.com/en-us/windows/win32/api/winbio/nf-winbio-winbiogetenrolledfactors
        WinBioGetEnrolledFactors

        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\S-1-12-1-2792295418-1230826404-2486600877-521991098
    .EXAMPLE
        Get-vlWindowsHelloStatusLocalUser
    #>


   # Get currently logged on user's SID
   $currentUserSID = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).value

   # Registry path to credential provider belonging for the PIN. A PIN is required with Windows Hello
   $registryItems = Get-vlRegSubkeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}"
   if (-not $registryItems ) {
      $result = [PSCustomObject]@{
         WindowsHelloEnabled = $false
      }

      return New-vlResultObject -result $result -score 7
   }
   if (-NOT[string]::IsNullOrEmpty($currentUserSID)) {

      $enroledFactors = Get-vlGetUserEnrolledFactors

      if ($enroledFactors.WinBioAvailable -and $enroledFactors.WinBioUsed) {
         $enroledFactors = $enroledFactors.WinBioEnroledFactors
      }
      else {
         $enroledFactors = @()
      }

      # If multiple SID's are found in registry, look for the SID belonging to the logged on user
      if ($registryItems.GetType().IsArray) {
         # LogonCredsAvailable needs to be set to 1, indicating that the PIN credential provider is in use
         if ($registryItems.Where({ $_.PSChildName -eq $currentUserSID }).LogonCredsAvailable -eq 1) {
            $result = [PSCustomObject]@{
               WindowsHelloEnabled = $true
               EnrolledFactors     = $enroledFactors
            }

            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               WindowsHelloEnabled = $false
               EnrolledFactors     = $enroledFactors
            }

            return New-vlResultObject -result $result -score 7
         }
      }
      else {
         if (($registryItems.PSChildName -eq $currentUserSID) -AND ($registryItems.LogonCredsAvailable -eq 1)) {
            $result = [PSCustomObject]@{
               WindowsHelloEnabled = $true
               EnrolledFactors     = $enroledFactors
            }

            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               WindowsHelloEnabled = $false
               EnrolledFactors     = $enroledFactors
            }

            return New-vlResultObject -result $result -score 7
         }
      }
   }
   else {
      return New-vlErrorObject("Not able to determine Windows Hello enrollment status")
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

   if ($params.Contains("all") -or $params.Contains("LUUIsAdmin")) {
      $isLocalAdmin = Get-vlIsLocalAdmin
      $Output += [PSCustomObject]@{
         Name         = "LUUIsAdmin"
         DisplayName  = "Local user is admin"
         Description  = "Checks if the local user is a member of the local Administrators group."
         Score        = $isLocalAdmin.Score
         ResultData   = $isLocalAdmin.Result
         RiskScore    = 70
         ErrorCode    = $isLocalAdmin.ErrorCode
         ErrorMessage = $isLocalAdmin.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUUWinBio")) {
      $windowsHelloStatus = Get-vlWindowsHelloStatusLocalUser
      $Output += [PSCustomObject]@{
         Name         = "LUUWinBio"
         DisplayName  = "Local user Windows Hello / biometrics"
         Description  = "Checks if Windows Hello is enabled and if the local user has enrolled factors."
         Score        = $windowsHelloStatus.Score
         ResultData   = $windowsHelloStatus.Result
         RiskScore    = 30
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTN6VhJoHMhSiO
# K5Jff/wXqkZVNiRGLZDwxeOipiRsUaCCAywwggMoMIICEKADAgECAhAV/4qQJS3s
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBqc9ityekDWs7mGABLyJHqpRuLSTEwp
# CKJCN+SvAF+xMA0GCSqGSIb3DQEBAQUABIIBABoFY4c7fbxwvd3RMr3LvnOoqHIb
# cXEMIfHSY7bxvIFUEuPxiWq9mJwnr5orjPoeyf8vmtGpPgsxLL/dynFQ4xz6Y8yt
# 4Aoe2F8hG+h8heQs5tZ5SQxDlgS3+zr+AEWcjGrQlkbLHTucVopJK+2EXL977z1p
# ycJcHC5GFhigRj7R4mjjLYSMu8y88vaiwb4D6rEExctb1dwaaoS3Z5dFG6DVaoek
# qeTAZmIlpvSNtU38oJ/D3O5w1Iq0t3aM1nrl2WSUGdSLcOlq5T1mggbrLjfcxt83
# aYLmL5u9f8WU5GcQ9mLIHl3+m+5NNpXIi4JWeIhZZzj0hqtai9Q05lnEBhQ=
# SIG # End signature block
