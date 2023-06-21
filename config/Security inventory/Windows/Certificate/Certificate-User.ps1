#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force
. $PSScriptRoot\..\Shared\StlParser.ps1 -Force

function Get-vlExpiredCertificateCheck {
   <#
    .SYNOPSIS
        Function that checks if certificates are expired or will expire in the next 30 or 60 days.
    .DESCRIPTION
        Function that checks if certificates are expired or will expire in the next 30 or 60 days.
    .OUTPUTS
        If root certificate auto update is enabled, the function returns a PSCustomObject with the following properties:
        expired: List of expired certificates
        willExpire30: List of certificates that will expire in the next 30 days
        willExpire60: List of certificates that will expire in the next 60 days
    .EXAMPLE
        Get-vlExpiredCertificateCheck
    #>

   try {
      $score = 10

      # get certs for user store
      $certs = Get-ChildItem -Path Cert:\CurrentUser -Recurse
      $expCets = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and $_.NotAfter -lt (Get-Date) } | Select-Object -Property FriendlyName, Issuer, NotBefore, NotAfter, Thumbprint
      $willExpire30 = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and ($_.NotAfter -gt (Get-Date) -and $_.NotAfter -lt (Get-Date).AddDays(30)) } | Select-Object -Property FriendlyName, Issuer, NotBefore, NotAfter, Thumbprint
      $willExpire60 = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and ($_.NotAfter -gt (Get-Date).AddDays(30) -and $_.NotAfter -lt (Get-Date).AddDays(60)) } | Select-Object -Property FriendlyName, Issuer, NotBefore, NotAfter, Thumbprint


      # convert Date object to ISO timestring
      $expCets = $expCets | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         $_
      }

      $willExpire30 = $willExpire30 | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         $_
      }

      $willExpire60 = $willExpire60 | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         $_
      }

      if ( $willExpire60.Length -gt 0 ) {
         $score = 7
      }

      if ( $willExpire30.Length -gt 0 ) {
         $score = 4
      }

      if ( $expCets.Length -gt 0 ) {
         $score = 0
      }

      $result = [PSCustomObject]@{
         expired      = $expCets
         willExpire30 = $willExpire30
         willExpire60 = $willExpire60
      }
      # Updates are enabled
      return New-vlResultObject -result $result -score $score
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlStlFromRegistryToMemory {
   <#
    .SYNOPSIS
        Function that gets the AuthRoot.stl file from the registry.
    .DESCRIPTION
        Function that gets the AuthRoot.stl file from the registry.
    .OUTPUTS
        Returns the path to the AuthRoot.stl file.
        If there returns an empty string.
    .EXAMPLE
        Get-vlStlFromRegistryToMemory
    #>

   try {
      #Get the AuthRoot.stl file from the registry
      $authRootStl = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate" -Value "EncodedCtl"

      #check if $authRootStl is not empty
      if ($authRootStl.Length -gt 0) {
         return $authRootStl
      }

      return ""
   }
   catch {
      return ""
   }
}

function Get-vlCompareCertTrustList($trustList, $certList) {
   <#
    .SYNOPSIS
        Function that compares two lists.
    .DESCRIPTION
        Function that compares two lists.
    .OUTPUTS
        Returns true if the lists are the same.
        Returns false if the lists are not the same.
    .EXAMPLE
        Get-vlCompareCertTrustList -trustList @("cert1", "cert2") -certList @("cert1", "cert2")
    #>

   try {
      #check if $trustList and $certList are not empty
      if ($trustList -and $certList) {
         #check if the Thumbprint of the certificate is in the trust list. If yes add to list known certificates else add to unknown certificates
         $unknownCerts = @()
         $knownCerts = @()
         foreach ($cert in $certList) {
            if ($cert.Thumbprint -in $trustList) {
               $knownCerts += $cert
            }
            else {
               $unknownCerts += $cert
            }
         }

         return [PSCustomObject]@{
            KnownCerts   = $knownCerts
            UnknownCerts = $unknownCerts
         }
      }

      return $false
   }
   catch {
      return $false
   }
}

function Get-vlGetCTLCheck {
   <#
    .SYNOPSIS
        Check if there are unknown certificates installed
    .DESCRIPTION
        Check if there are unknown certificates installed
    .OUTPUTS
        Returns the unknown certificates for LocalMachine and CurrentUser
    .EXAMPLE
        Get-vlGetCTLCheck
    #>

   <#
    # Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.Issuer -eq $_.Subject }
    # Get-ChildItem -Path cert:\CurrentUser\My | Where-Object { $_.Issuer -eq $_.Subject }
    # Get-ChildItem -Path cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject }
    # Get-ChildItem -Path cert:\CurrentUser\Root | Where-Object { $_.Issuer -eq $_.Subject }
    #>

   #last time the AuthRoot.stl file was synced
   try {
      $score = 10

      $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()

      #Load Stl
      $localAuthRootStl = Get-vlStlFromRegistryToMemory #Get-vlStlFromRegistry

      # Get all certificates from the local machine
      $localMachineCerts = Get-ChildItem cert:\LocalMachine\Root

      #add all certificates that are not expired from the current user
      $currentUserCerts = Get-ChildItem cert:\CurrentUser\Root | Select-Object -Property Thumbprint, Issuer, Subject, NotAfter, NotBefore

      # filter out certificates from $currentUserCerts that are contained in $localMachineCerts
      $currentUserCerts = $currentUserCerts | Where-Object { $_.Thumbprint -notin $localMachineCerts.Thumbprint }

      # convert NotAfter and NotBefore to string iso format
      $currentUserCerts = $currentUserCerts | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         return $_
      }

      #extract CTL
      $trustedCertList = Get-vlCertificateTrustListFromBytes -bytes $localAuthRootStl

      # Create the result object
      $result = [PSCustomObject]@{
         Unknown     = (Get-vlCompareCertTrustList -trustList $trustedCertList -certList $currentUserCerts).UnknownCerts
         CurrentUser = $currentUser.Name
      }

      if ($result.Unknown.Count -gt 0) {
         $score -= 5
      }

      return New-vlResultObject -result $result -score $score
   }
   catch {
      return New-vlErrorObject -context $_
   }

}

function Get-vlCertificateCheck {
   <#
    .SYNOPSIS
        Function that performs the Certificate check and returns the result to uberAgent.
    .DESCRIPTION
        Function that performs the Certificate check and returns the result to uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlCertificateCheck
    #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   <# disabled for now since there is no real security impact if the certificate is expired
   if ($params.Contains("all") -or $params.Contains("CUExpCerts")) {
      $protectedRoots = Get-vlExpiredCertificateCheck
      $Output += [PSCustomObject]@{
         Name         = "CUExpCerts"
         DisplayName  = "Expired certificates"
         Description  = "Checks if there are expired certificates installed within the CurrentUser store."
         Score        = $protectedRoots.Score
         ResultData   = $protectedRoots.Result
         RiskScore    = 20
         ErrorCode    = $protectedRoots.ErrorCode
         ErrorMessage = $protectedRoots.ErrorMessage
      }
   }
   #>
   if ($params.Contains("all") -or $params.Contains("CUTrByWin")) {
      $ctlCheck = Get-vlGetCTLCheck
      $Output += [PSCustomObject]@{
         Name         = "CUTrByWin"
         DisplayName  = "Certificates trusted by Windows - User"
         Description  = "Checks if there are unknown certificates installed within the CurrentUser store."
         Score        = $ctlCheck.Score
         ResultData   = $ctlCheck.Result
         RiskScore    = 70
         ErrorCode    = $ctlCheck.ErrorCode
         ErrorMessage = $ctlCheck.ErrorMessage
      }
   }

   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-vlCertificateCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDvS/n/bKBOCZsm
# uwCAZMLtd1RLYfJmVQz/3ifUlKsR6aCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgtwu9j4jhWEBB
# vwB6qynBR37sXJD8J5YcJQbjD/UCyhUwDQYJKoZIhvcNAQEBBQAEggIARvMKS4g3
# oE5mICHVqU3/to5wtYIgG+783CkARAeJhppld8Uh5zBuGznnKMaBqF/J2VdtuJ6K
# 3DmI1R8WXZrPs60+SfaGv4JHafpNRtprpYL19hEkKTapry4nd77OOFajTtvDZT74
# EqAVbsh2jxurMCmD6hzR8kObl7OACD0ZEcbXlvSRWHzOu/zBd7dcRttzGFEX/IqR
# qtrbaBUnNMxFtUMNySezkjOs6WCT59MLxOj7dhb/hWQWlhQu7UjRUSDwMBjCw/vP
# /sHs4hkPTYiSK96KG71ko1TiCgiRRDhoHBkuIGAVkNandrLS/emlIFIK5RgbXguq
# SO14GHq6j5y4Zd3LfvYcrveHSjOC+DRXF45Ory9ViiQRmcz7PT357xtwJ7+Zbzdl
# y4DqJXZrq00yRlIiS10c9iyQegtV3UbWOQVZwSMZdDJVylS4Y8v+vVIvithp9whO
# Aoezfcxh2M0WkhhNbFBT2rNyG5BU8vzKzQQBklE6wHHZsITvdKxYlj1YX65xjIY4
# Mrpn5E4YG/IC64GVV6FCbw8cnEz2ImvBW/vNDd4N4kB/kdksp4VH2tL0h1XHKCm5
# /cTohSBF7QOGw/lm16F38wW1+rRLr5EIoKUXyjqEGwA7GUCZUiSYsk5+3aDirpXS
# yx3ltbuK7hJfV6wk+4MkuAlshBcoQ65KeGA=
# SIG # End signature block
