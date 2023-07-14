#Requires -RunAsAdministrator
#Requires -Version 3.0

. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#https://mcpforlife.com/2020/04/14/how-to-resolve-this-state-value-of-av-providers/
if (-not ("AV_ProductState" -as [type])) {
   Add-Type -TypeDefinition @"
   public enum AV_ProductState
   {
      Off = 0x0000,
      On = 0x1000,
      Snoozed = 0x2000,
      Expired = 0x3000
   }
"@

   Add-Type -TypeDefinition @"
   public enum AV_SignatureStatus
   {
      UpToDate = 0x00,
      OutOfDate = 0x10
   }
"@

   Add-Type -TypeDefinition @"
   public enum AV_ProductOwner
   {
      NonMs = 0x000,
      Windows = 0x100
   }
"@

   Add-Type -TypeDefinition @"
   public enum AV_ProductFlags
   {
      SignatureStatus = 0x000000F0,
      ProductOwner = 0x00000F00,
      ProductState = 0x0000F000
   }
"@
}

function Get-vlAntivirusStatus {
   <#
    .SYNOPSIS
        Get the status of the antivirus software
    .DESCRIPTION
        Get the status of the antivirus software
        This cmdlet is only available on the Windows platform.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the status of the antivirus software
    .EXAMPLE
        Get-vlAntivirusStatus
    #>

   process {
      try {
         $result = @()
         $score = 0
         $riskScore = 100

         $isWindowsServer = Get-vlIsWindowsServer
         $isWindows7 = Get-vlIsWindows7
         $defenderStatus = [PSCustomObject]@{}

         if ($isWindows7 -ne $true) {
            $instances = Get-MpComputerStatus

            $defenderStatus = [PSCustomObject]@{
               AMEngineVersion                 = if ($instances.AMEngineVersion) { $instances.AMEngineVersion } else { "" }
               AMServiceEnabled                = if ($instances.AMServiceEnabled) { $instances.AMServiceEnabled } else { "" }
               AMServiceVersion                = if ($instances.AMServiceVersion) { $instances.AMServiceVersion } else { "" }
               AntispywareEnabled              = if ($instances.AntispywareEnabled) { $instances.AntispywareEnabled } else { "" }
               AntivirusEnabled                = if ($instances.AntivirusEnabled) { $instances.AntivirusEnabled } else { "" }
               AntispywareSignatureLastUpdated = if ($instances.AntispywareSignatureLastUpdated) { $instances.AntispywareSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ss") } else { "" }
               AntispywareSignatureVersion     = if ($instances.AntispywareSignatureVersion) { $instances.AntispywareSignatureVersion } else { "" }
               AntivirusSignatureLastUpdated   = if ($instances.AntivirusSignatureLastUpdated) { $instances.AntivirusSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ss") } else { "" }
               QuickScanSignatureVersion       = if ($instances.QuickScanSignatureVersion) { $instances.QuickScanSignatureVersion } else { "" }
            }
         }

         if ($isWindowsServer -eq $false) {
            if ($isWindows7 -eq $true) {
               $instances = Get-CimInstance -ClassName AntiSpywareProduct -Namespace "root\SecurityCenter2"
            }
            else {
               $instances = Get-CimInstance -ClassName AntiVirusProduct -Namespace "root\SecurityCenter2"
            }

            $avEnabledFound = $false

            foreach ($instance in $instances) {
               $avEnabled = $([AV_ProductState]::On.value__ -eq $($instance.productState -band [AV_ProductFlags]::ProductState) )
               $avUp2Date = $([AV_SignatureStatus]::UpToDate.value__ -eq $($instance.productState -band [AV_ProductFlags]::SignatureStatus) )

               if ($avEnabled) {
                  $avEnabledFound = $true
                  if ($avUp2Date) {
                     $score = 10
                  }
                  else {
                     $score = 5
                  }
               }

               if ($instance.displayName -eq "Windows Defender" -or "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}" -eq $instance.instanceGuid) {

                  if ($avEnabled -eq $false -or $isWindows7 -eq $true) {
                     $result += [PSCustomObject]@{
                        Enabled  = $avEnabled
                        Name     = $instance.displayName
                        UpToDate = $avUp2Date
                     }
                  }
                  else {
                     $result += [PSCustomObject]@{
                        Enabled  = $avEnabled
                        Name     = $instance.displayName
                        UpToDate = $avUp2Date
                        Defender = $defenderStatus
                     }

                     $score -= Get-vlTimeScore($defenderStatus.AntispywareSignatureLastUpdated)
                     $score -= Get-vlTimeScore($defenderStatus.AntivirusSignatureLastUpdated)
                  }
               }
               else {
                  $result += [PSCustomObject]@{
                     Enabled  = $avEnabled
                     Name     = $instance.displayName
                     UpToDate = $avUp2Date
                  }
               }
            }

            if (-not $avEnabledFound) {
               $score = 0
            }
         }
         else {
            $result = @()
            $score = 0

            if ($defenderStatus -and $defenderStatus.AMServiceEnabled -and $defenderStatus.AntispywareEnabled -and $defenderStatus.AntivirusEnabled) {
               $score = 10

               $score -= Get-vlTimeScore($defenderStatus.AntispywareSignatureLastUpdated)
               $score -= Get-vlTimeScore($defenderStatus.AntivirusSignatureLastUpdated)

               $result += [PSCustomObject]@{
                  Enabled  = $true
                  Name     = "Windows Defender"
                  UpToDate = if ($score -eq 10) { $true } else { $false }
                  Defender = $defenderStatus
               }
            }
            elseif ($defenderStatus) {
               $result += [PSCustomObject]@{
                  Enabled  = $false
                  Name     = "Windows Defender"
                  UpToDate = if ($score -eq 10) { $true } else { $false }
                  Defender = $defenderStatus
               }
            }
            else {
               return New-vlErrorObject -message "Status could not be determined because SecurityCenter2 is not available on Windows Server." -errorCode 1 -context $_
            }
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
      catch {
         return New-vlErrorObject($_)
      }
   }
}

function Get-vlAntivirusCheck {
   <#
    .SYNOPSIS
        Function that performs the antivirus check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the antivirus check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlAntivirusCheck -amsi -avStatus
    #>

   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   if ($params.Contains("all") -or $params.Contains("AVState")) {
      $avStatus = Get-vlAntivirusStatus
      $Output += [PSCustomObject]@{
         Name         = "AVState"
         DisplayName  = "Antivirus status"
         Description  = "This test determines whether an antivirus product is installed and its current status. If the test is performed on a Windows server operating system, due to technical limitations, only the Defender status is evaluated. If Windows Defender is enabled, the test will provide additional information, such as the status of the last signature update and the current signature version."
         Score        = $avStatus.Score
         ResultData   = $avStatus.Result
         RiskScore    = $avStatus.RiskScore
         ErrorCode    = $avStatus.ErrorCode
         ErrorMessage = $avStatus.ErrorMessage
      }
   }

   Write-Output $output
}


try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlAntivirusCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCATfPA2zVJxNEZe
# 71dSqCZ3sSZfGyOA7VV0yYaOr21pHaCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg5fe8e1CtNdnj
# OwUrU8nj/qWJ+qmr8Zh/QA9XnVO4hEwwDQYJKoZIhvcNAQEBBQAEggIA365PQVyp
# 1os2a56hjUSj2ppYGL719aYIRHt/JM0GEo7wR3HlMrZ6sViT5yn2kpZ7S8B/PS3y
# v2iWdES6KO4piuxzXdl9em/FYynzXvkqFuIpYvQNi3nHnzs7R/HZjwSkcKo04kc1
# Am6zamfGab1G1SQiwZ6Q0HSYrUslPsf+WZzpThfMJrZgQY4pS0RH+Bxjw1IKaRfK
# +TE5HCgSwn753ykO1egen3Cj93Rpr7dnl+VITJJSksm7smTvmNr/fwU0cEw3ZdFe
# adAmUrIX0bLkg6qVEW6HuPd4b0o70JGpdhbbTc3r+LiZQs/VA336MRq0yHn1eL/c
# KMplRGyx6fnPgOnLURPsepTZnxke2UE7hGyx2+/H/7SgV11XmLF8b1wWtI6stfjz
# HrtZpJM2dKipy5YU+JCCeyX3ENwL+nd0VSXQ+mmE2ujGpDOiiJ7GigsHr/0Y1MZc
# G6rUd0/0hxPJSqyHkhBDkSeVlHdgwkLdhL8EU3o4bDTbE5Uf2Qpp+/couRaO8gfx
# ku8Jyaxjhk7dbNQwq99OlMfyNQu+SO6KucWc1JPEqBMbXn40Ac/TxIdRkrj/n0u2
# d+UjiSNWnYM7ScE5LaPUTUObciWajsCWZ2So6SKlHVzc+PPa0iCdWCrjvKqrCN9b
# 4UbQsT40Lc9Rqe3c7slTSCbIsp4whVKRd+k=
# SIG # End signature block
