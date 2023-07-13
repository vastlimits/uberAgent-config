
. $PSScriptRoot\..\Shared\Helper.ps1 -Force
. $PSScriptRoot\..\Shared\AppLinkHelper.ps1 -Force


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

function Get-CheckHTAEnabled {
   <#
    .SYNOPSIS
        Checks if HTA is enabled on the system.
    .DESCRIPTION
        Checks if HTA is enabled on the system.
    .LINK
        https://uberagent.com
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-CheckHTAEnabled
    #>

   try {
      $startProc = ""
      $score = 10
      $riskScore = 80

      #$htaExecuteStatus = Run-vlHtaCode $htacode
      $htaRunBlocked = Test-vlBlockedProgram -ProgramPath "mshta.exe"

      $defaultLink = $true
      $startCmd = [AppLinkHelper]::AssocQueryString(".hta")

      if ($null -ne $startCmd -and $startCmd -ne "") {
         $startProc = (Split-Path $startCmd -Leaf)

         # check if $startProc contains space and if so, get the first part
         if ($startProc.Contains(" ")) {
            $startProc = $startProc.Split(" ")[0]
         }
      }
      else {
         $startProc = $null
      }

      # check if $status contains "mshta.exe"

      if ($startCmd.Contains("mshta.exe")) {
         $defaultLink = $true
      }
      else {
         $defaultLink = $false
      }

      if ($htaRunBlocked -ne $true) {
         $score -= 7
      }

      if ($defaultLink -eq $true) {
         $score -= 3
      }

      $result = [PSCustomObject]@{
         RunBlocked  = $htaRunBlocked
         OpenWith    = $startProc
         DefaultLink = $defaultLink
      }

      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-WindowsConfigurationCheck {
   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()


   # disabled for now - since we would trigger a lot of false positives
   if ($params.Contains("all") -or $params.Contains("WCHta")) {
      $checkHtaEnabled = Get-CheckHTAEnabled
      $Output += [PSCustomObject]@{
         Name         = "WCHta"
         DisplayName  = "WindowsConfiguration HTA"
         Description  = "This test validates whether HTA (HTML Application) execution is enabled for the current user. HTA files can be used to execute malicious scripts or actions if not properly controlled."
         Score        = $checkHtaEnabled.Score
         ResultData   = $checkHtaEnabled.Result
         RiskScore    = $checkHtaEnabled.RiskScore
         ErrorCode    = $checkHtaEnabled.ErrorCode
         ErrorMessage = $checkHtaEnabled.ErrorMessage
      }
   }

   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCANkbZCxg5Kz/JN
# 0DOZP9d+3ToWnkumufdmrG2wqTRKQ6CCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgmeTmdOwUb8HZ
# WUTSiDFvFBnqAIiCdUORGGKjxMb/cO0wDQYJKoZIhvcNAQEBBQAEggIACgXhJaZp
# zvIxZvuJsCXpMGH+oRVPtk8FpSDpBsPhNLY2MOpQJoYy4I6xupZb8UmYa3ERq0mZ
# GKoPplyOgqpEp/qBw8J+2q+BILqcqoKunr4z7yu1oBVVF2w33n7MF2cq7QJzymkv
# pSfFK3ubFbyrbU8OMkgi5dewHaxEvjT7ICYFuE4J5Hh8SpNE/nkwelQWn3/ZuUw6
# e9RudPUlekYp1fvgF6symPMo+Bwns3emymTaBQEHaZMVodhUyEIzakib8s97Wj2Q
# nnecQlFjaviEWdbM0DpjHW73ZoQHTx8zo866dKXIGFodxd5p8JmZhX7TdN4YTsdW
# qt5wrRlHkk6+xlC6FrzHburyr5Ej5oBEz92Uz+8C40sYrueO92XcPdaJVq20q4l5
# OG1Q2y1Am2Ss0v3KS/FHvMg1mWyFbrz488y2LxrhSPgNFdG/9pk8Dd7QvzOy2o4p
# t3EeDhyzFm+eWIsrG+dWSWoYZMuusww2CzZb4gIWmHaHpEFpV5ZIygsk1U1a2b6t
# pocHqVQ8GkrRIY2jakEb4Ajrt0OM6A+Arj+O+irNk6MjNZlopcBJ9tUpFr5k1xof
# vDR+W2skHLn9ZsYmSmW5GandBs9Zb+UMT6Fv2jqpZffHnoA7jXnDKPypeR9Wpsan
# ELh9f5j5QzizMGKhQL1OxVy5Fh1Hene2ozc=
# SIG # End signature block
