. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlServiceLocations {
   <#
   .SYNOPSIS
       Checks whether services are located outside common locations
   .DESCRIPTION
       Checks whether services are located outside common locations
   .LINK

   .NOTES

   .OUTPUTS
       A [psobject] containing services located outside common locations. Empty if nothing was found.
   .EXAMPLE
       Get-vlServiceLocations
   #>

   param (

   )

   process {
      $riskScore = 100

      try {
         $result = @()
         Get-vlRegSubkeys -Hive HKLM -Path 'SYSTEM\CurrentControlSet\Services' | Where-Object { $_.ImagePath } | ForEach-Object -process {
            $ImagePath = $PSItem.ImagePath
            $ServiceName = $PSItem.PSChildName
            if ($ImagePath -inotmatch '^(\\\?\?\\)?\\?SystemRoot.*$|^(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\WINDOWS\\(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\Program Files( \(x86\))?\\.*$|^(\\\?\?\\)?"?C:\\WINDOWS\\Microsoft\.NET\\.*$|^(\\\?\?\\)?"?C:\\ProgramData\\Microsoft\\Windows Defender\\.*$') {
               $result += [PSCustomObject]@{
                  Service   = $ServiceName
                  ImagePath = $ImagePath
               }
            }

         }

         if (-not $result) {
            # No services outside common locations found
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         else {
            # Services outside common location found
            return New-vlResultObject -result $result -score 1 -riskScore $riskScore
         }
      }
      catch {

         return New-vlErrorObject($_)
      }
      finally {

      }

   }

}

function Get-vlServiceDLLLocations {
   <#
    .SYNOPSIS
        Checks whether service.dll files are located outside common locations
    .DESCRIPTION
        Checks whether service.dll files are located outside common locations
    .LINK

    .NOTES

    .OUTPUTS
        A [psobject] containing services with service.dll files located outside common locations. Empty if nothing was found.
    .EXAMPLE
        Get-vlServiceDLLLocations
    #>

   param (

   )

   process {
      $riskScore = 90

      try {
         $result = @()
         Get-ItemProperty hklm:\SYSTEM\CurrentControlSet\Services\*\Parameters | Where-Object { $_.servicedll } | ForEach-Object -process {

            $ServiceDLL = $PSItem.ServiceDLL
            $ServiceName = ($PSItem.PSParentPath).split('\\')[-1]
            if ($ServiceDLL -inotmatch '^C:\\WINDOWS\\system32.*$') {

               $result += [PSCustomObject]@{
                  Service    = $ServiceName
                  ServiceDLL = $ServiceDLL
               }
            }

         }

         if (-not $result) {
            # No service.dll file outside common locations found
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         else {
            # Service.dll file outside common location found
            return New-vlResultObject -result $result -score 1 -riskScore $riskScore
         }
      }
      catch {

         return New-vlErrorObject($_)
      }
      finally {

      }

   }

}


function Get-vlWindowsServicesCheck {
   <#
   .SYNOPSIS
       Function that performs the Windows services check and returns the result to the uberAgent.
   .DESCRIPTION
       Function that performs the Windows services check and returns the result to the uberAgent.
   .NOTES
       The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
       Specific tests can be called by passing the test name as a parameter to the script args.
       Passing no parameters or -all to the script will run all tests.
   .LINK
       https://uberagent.com
   .OUTPUTS
       A list with vlResultObject | vlErrorObject [psobject] containing the test results
   .EXAMPLE
       Get-vlWindowsServicesCheck
   #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("ServiceLocations")) {
      $ServiceLocations = Get-vlServiceLocations
      $Output += [PSCustomObject]@{
         Name         = "Locations"
         DisplayName  = "Uncommon locations"
         Description  = "This test evaluates whether services are running in unusual or unexpected locations on the system. Unusual or unexpected locations in this case means outside of folders such as C:\WINDOWS\ or C:\Program Files, which may indicate a potential security issue or a compromise."
         Score        = $ServiceLocations.Score
         ResultData   = $ServiceLocations.Result
         RiskScore    = $ServiceLocations.RiskScore
         ErrorCode    = $ServiceLocations.ErrorCode
         ErrorMessage = $ServiceLocations.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("ServiceDLLLocations")) {
      $ServiceDLLLocations = Get-vlServiceDLLLocations
      $Output += [PSCustomObject]@{
         Name         = "Service.dll"
         DisplayName  = "Uncommon locations of service.dll"
         Description  = "This test scans the Windows registry for service DLL files and determines whether a DLL file is located outside the Windows system directory. DLL files are important components used by various services and applications of the Windows operating system. Malicious actors try to execute code and gain persistence by registering their malicious DLL files."
         Score        = $ServiceDLLLocations.Score
         ResultData   = $ServiceDLLLocations.Result
         RiskScore    = $ServiceDLLLocations.RiskScore
         ErrorCode    = $ServiceDLLLocations.ErrorCode
         ErrorMessage = $ServiceDLLLocations.ErrorMessage
      }
   }

   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-vlWindowsServicesCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCHsC72S1xMNjva
# TEDzpP2imKdyeKN3tfjYONi3954/XKCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgH3+/Q+ipv8qK
# 87TC7rXZ0eVumQz+E2ZJOOOY7qRVv+gwDQYJKoZIhvcNAQEBBQAEggIAsI+rcZWT
# yt7VlrjlfJmYw/FlpwrsnazY/z8ZjU5raLwAfcL77kYPdOulzbM8OebhhBbWor/+
# YYlLOTFxzV/9NOtuwTpKN85MoSj5ahQhbiZy3MvsZtnj1sSaQYQ09zw5bXVMwELg
# xftnJzfLxtgx5z5mDs9mc5p10dYvAnMchVzhk49QpSXm3TVTviA+E6CtjywTLTDQ
# fvGSfnb2Cn/RWMJ/cvR+2FLrroBY0eG7Yv8xoad0SfHpYiKfd/ndv/DsjJz1+maI
# dUQK631qwovfq1rJj2gmwS7SMaWRGK+RaTHr+JzLT3VIskBBmrCivD4yBVC0WdLA
# afTfB5AefKvLzFP0HU169j2i8Mp5GnfHJsoAYMHRXTxU2FVdUHzZVN67FULBd1wl
# pK0mf3qlaZU3VFaUsBcQDEK2lf6fonLDVKrgIWRG3301JIPBaOyNrN1W5NwqKh89
# a5XLGD4Hcx/rh2mOf1vQF4rU8CkFitvkoM/bN1NxRCO5G+3AyFw/CEHCSk0TOki7
# Q0Jauoc85sIOiLseE0vC+bU7bjMDfRs+yQXLdv8469jJgSwNcguOZs5C0go9bHU/
# RifsIexmz72gyfuzna8eNpwJy1wB3qAoiey7JX0ixUxNF7Gx9u4o+M6IBxqGDYnN
# WplSVz+AXhOJgvCgeEWA6H4x1ay3na2U2dg=
# SIG # End signature block
