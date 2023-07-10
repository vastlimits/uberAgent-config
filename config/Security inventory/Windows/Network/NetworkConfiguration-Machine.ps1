#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlNetworkConfigurationSMBv1 {
   <#
   .SYNOPSIS
       Checks whether SMBv1 is enabled
   .DESCRIPTION
       Checks whether SMBv1 is enabled
   .OUTPUTS
       If SMBv1 is enabled, the function returns a PSCustomObject with the following properties:
       enabled: true
       If SMBv1 is disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES
       Ref: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=client
   .EXAMPLE
       Get-vlNetworkConfigurationSMBv1
   #>

   try {
      $riskScore = 100
      $OSVersion = Get-vlOsVersion

      if ([version]$OSVersion -ge [version]'6.0' -and [version]$OSVersion -lt [version]'6.2') {
         $SMB1ClientServiceDependency = Get-Service -name LanManWorkstation -RequiredServices -ErrorAction Stop | Where-Object -FilterScript { $_.Name -eq 'MrxSmb10' }
         if ($SMB1ClientServiceDependency) {
            $SMBv1 = 1
         }
         else {
            $SMBv1 = 2
         }
      }
      else {
         $SMBv1 = (Get-CimInstance -query "select * from  Win32_OptionalFeature where name = 'SMB1Protocol'").InstallState
      }

      if ($SMBv1 -eq 2) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # SMBv1 is disabled
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      elseif ($SMBv1 -eq 1) {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # SMBv1 is enabled
         return New-vlResultObject -result $result -score 2 -riskScore $riskScore
      }
      else {
         return New-vlErrorObject("SMBv1 install state must be 1 or 2 but is $SMBv1")
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationSMBSigning {
   <#
   .SYNOPSIS
       Checks whether SMB signing enabled
   .DESCRIPTION
       Checks whether SMB signing enabled
   .OUTPUTS
       If SMB signing is enabled, the function returns a PSCustomObject with the following properties:
       enabled: true
       If SMB signing is disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES
       Ref: https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102
   .EXAMPLE
       Get-vlNetworkConfigurationSMBSigning
   #>

   $riskScore = 40

   try {
      $SMBv1 = Get-vlNetworkConfigurationSMBv1

      if ($SMBv1.Result -like '*true*') {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"
         $SMBSigningEnabled = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "EnableSecuritySignature"

         if ($SMBSigningRequired -eq 1) {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         elseif ($SMBSigningRequired -eq 0 -and $SMBSigningEnabled -eq 1) {
            $result = [PSCustomObject]@{
               state = "Enabled"
            }
            # SMB signing is enabled but not required
            return New-vlResultObject -result $result -score 2 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2 -riskScore $riskScore
         }
      }
      elseif ($SMBv1.Result -like '*false*') {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"

         if ($SMBSigningRequired -eq 1) {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2 -riskScore $riskScore
         }

      }
      else {
         Throw "Return of Get-vlNetworkConfigurationSMBv1 is invalid"
         return New-vlErrorObject($Error)
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationNetBIOS {
   <#
   .SYNOPSIS
       Checks whether NetBIOS is enabled
   .DESCRIPTION
       Checks whether NetBIOS is enabled
   .OUTPUTS
       If NetBIOS is enabled, the function returns a PSCustomObject with the following properties:
       enabled: true
       If NetBIOS is disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationNetBIOS
   #>

   try {
      $riskScore = 20

      if ((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object -Property 'TcpipNetbiosOptions' -eq 1).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # NetBIOS is disabled
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # NetBIOS is enabled
         return New-vlResultObject -result $result -score 3 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationWINS {
   <#
   .SYNOPSIS
       Checks whether WINS is used
   .DESCRIPTION
       Checks whether WINS is used
   .OUTPUTS
       If WINS is used, the function returns a PSCustomObject with the following properties:
       enabled: true
       If WINS is used, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationWINS
   #>

   try {
      $riskScore = 20

      if (((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter IPEnabled=TRUE | Where-Object -Property 'WINSPrimaryServer' -ne $null).ServiceName).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # WINS is not in usage
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # WINS is in usage
         return New-vlResultObject -result $result -score 3 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationSSLTLSLocalMachine {
   <#
   .SYNOPSIS
       Checks whether only secure protocols are used
   .DESCRIPTION
      Checks whether only secure protocols are used
   .OUTPUTS
       If only secure protocols are used, the function returns a PSCustomObject with the following properties:
       SecureProtocolsOnly: true
       If not only secure protocols are used, the function returns a PSCustomObject with the following properties:
       SecureProtocolsOnly: false
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationSSLTLSLocalMachine
   #>

   $riskScore = 40

   try {

      try {
         # 10240 = TLS 1.2 & TLS 1.3
         # 8192  = TLS 1.3
         # 2048  = TLS 1.2
         $DesiredValues = @(10240, 8192, 2048)

         $SecureProtocols = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Value SecureProtocols -IncludePolicies $true

         if ($DesiredValues -contains $SecureProtocols) {
            $result = [PSCustomObject]@{
               SecureProtocolsOnly = $true
            }

            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               SecureProtocolsOnly = $false
            }

            return New-vlResultObject -result $result -score 4 -riskScore $riskScore
         }
      }
      catch {
         return New-vlErrorObject($_)
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}


function Get-vlNetworkConfigurationCheck {
   <#
   .SYNOPSIS
       Function that performs the network configuration check and returns the result to the uberAgent.
   .DESCRIPTION
       Function that performs the network configuration check and returns the result to the uberAgent.
   .NOTES
       The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
       Specific tests can be called by passing the test name as a parameter to the script args.
       Passing no parameters or -all to the script will run all tests.
   .LINK
       https://uberagent.com
   .OUTPUTS
       A list with vlResultObject | vlErrorObject [psobject] containing the test results
   .EXAMPLE
       Get-vlNetworkConfigurationCheck
   #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("NCSMBv1")) {
      $SMBv1 = Get-vlNetworkConfigurationSMBv1
      $Output += [PSCustomObject]@{
         Name         = "NCSMBv1"
         DisplayName  = "Network Configuration SMBv1"
         Description  = "Checks whether SMBv1 is enabled."
         Score        = $SMBv1.Score
         ResultData   = $SMBv1.Result
         RiskScore    = $SMBv1.RiskScore
         ErrorCode    = $SMBv1.ErrorCode
         ErrorMessage = $SMBv1.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCSMBSign")) {
      $SMBSigning = Get-vlNetworkConfigurationSMBSigning
      $Output += [PSCustomObject]@{
         Name         = "NCSMBSign"
         DisplayName  = "Network Configuration SMB Signing"
         Description  = "Checks whether SMB signing is enabled."
         Score        = $SMBSigning.Score
         ResultData   = $SMBSigning.Result
         RiskScore    = $SMBSigning.RiskScore
         ErrorCode    = $SMBSigning.ErrorCode
         ErrorMessage = $SMBSigning.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCNetBIOS")) {
      $NetBIOS = Get-vlNetworkConfigurationNetBIOS
      $Output += [PSCustomObject]@{
         Name         = "NCNetBIOS"
         DisplayName  = "Network configuration NetBIOS"
         Description  = "Checks whether NetBIOS is enabled."
         Score        = $NetBIOS.Score
         ResultData   = $NetBIOS.Result
         RiskScore    = $NetBIOS.RiskScore
         ErrorCode    = $NetBIOS.ErrorCode
         ErrorMessage = $NetBIOS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCWINS")) {
      $WINS = Get-vlNetworkConfigurationWINS
      $Output += [PSCustomObject]@{
         Name         = "NCWINS"
         DisplayName  = "Network configuration WINS"
         Description  = "Checks whether WINS is enabled."
         Score        = $WINS.Score
         ResultData   = $WINS.Result
         RiskScore    = $WINS.RiskScore
         ErrorCode    = $WINS.ErrorCode
         ErrorMessage = $WINS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("MNCSSLTLS")) {
      $SSLTLS = Get-vlNetworkConfigurationSSLTLSLocalMachine
      $Output += [PSCustomObject]@{
         Name         = "MNCSSLTLS"
         DisplayName  = "Network configuration SSL/TLS - Machine"
         Description  = "Checks whether only secure protocols are used"
         Score        = $SSLTLS.Score
         ResultData   = $SSLTLS.Result
         RiskScore    = $SSLTLS.RiskScore
         ErrorCode    = $SSLTLS.ErrorCode
         ErrorMessage = $SSLTLS.ErrorMessage
      }
   }

   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-vlNetworkConfigurationCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDFYeh81955NU4q
# OrrtNaDw9enb3LHn8SBTgbeFFrNTE6CCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgli97XuXmEwIf
# /YW5BNUHUmUH291i5tW/wSpCKkRVe2YwDQYJKoZIhvcNAQEBBQAEggIAoly3dWWB
# rchmwBO4mcEDWdxgl/9df3XWmbYovkhlr8zoUvIQXf9D5o+l3lbggJVDQcE9tQeW
# 5i9glxMLr+3/TstC3RkQhZw6/8J/GBROia+oXmHnNiaxQq02nmxYrK2zLuInOmnz
# ApDMZdUqvee0EADLH2V0LQTfNizBCPa+silLOBMhObKMXyU/qZlRxBTk9vk+04Ao
# XQ4hb88XufkMKnvcrDTnHpvybyC1j3QszRq779NIod+smePBwHQVYOLRM9BjCLk7
# l+Ygh4f7Lng6k//eAI5iD3Tix7YeJcsvAS4BKUts6yXjIzAnpCIhBaBwBgxegbfm
# B8LydK163VEm48Y5CGdQ3BwwUHcIbQIrK+rbdbUNMMfviXLevJXTlX+jOdDlmO0X
# 9h2oxcLoYBim4xHOQP6Bb9/6Ici1bahGqaUKUigAMyA1UekodQMF6UouSFoWXott
# eZIcKX27QBxKQ8zdSTdUBzuyId60ErftYqH6iHzsrvkaa8uOEx3er5gM0mz5Sgs4
# CZ5CroB8FH/Y3VBgdZq0ZEwQp69AykZ58mgsv4yK3XEsukYERCHXYYSbBQ0C3nRJ
# 4Ce7fIXcBeYH7zowjuNA/z6xfAVuL27n657zfmzH47u5nvSzB3NNsIAqei1rY8sF
# o1LOX/xtHvSM4GPU7VCbe+plTD6O+M4ofOA=
# SIG # End signature block
