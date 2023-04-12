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
      try {
         $ServiceArray = @()
         Get-vlRegSubkeys -Hive HKLM -Path 'SYSTEM\CurrentControlSet\Services' | Where-Object { $_.ImagePath } | ForEach-Object -process {
            $ImagePath = $PSItem.ImagePath
            if ($ImagePath -inotmatch '^(\\\?\?\\)?\\?SystemRoot.*$|^(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\WINDOWS\\(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\Program Files( \(x86\))?\\.*$|^(\\\?\?\\)?"?C:\\WINDOWS\\Microsoft\.NET\\.*$|^(\\\?\?\\)?"?C:\\ProgramData\\Microsoft\\Windows Defender\\.*$') {
               $ServiceArray += $ImagePath
            }

         }

         if ($ServiceArray.Count -eq 0) {
            $result = [PSCustomObject]@{
               Services = ""
            }
            # No services outside common locations found
            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               Services = $ServiceArray
            }
            # Services outside common location found
            return New-vlResultObject -result $result -score 1
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
      try {
         $ServiceArray = @()
         $ServiceDLLArray = @()
         Get-ItemProperty hklm:\SYSTEM\CurrentControlSet\Services\*\Parameters | Where-Object { $_.servicedll } | ForEach-Object -process {

            $ServiceDLL = $PSItem.ServiceDLL
            $ServiceName = ($PSItem.PSParentPath).split('\\')[-1]
            if ($ServiceDLL -inotmatch '^C:\\WINDOWS\\system32.*$') {

               $ServiceArray += $ServiceName
               $ServiceDLLArray += $ServiceDLL
            }

         }

         if ($ServiceArray.Count -eq 0) {
            $result = [PSCustomObject]@{
               Services    = ""
               ServiceDLLs = ""
            }
            # No service.dll file outside common locations found
            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               Services    = $ServiceArray
               ServiceDLLs = $ServiceDLLArray
            }
            # Service.dll file outside common location found
            return New-vlResultObject -result $result -score 1
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
         Description  = "Checks whether services are running in uncommon locations"
         Score        = $ServiceLocations.Score
         ResultData   = $ServiceLocations.Result
         RiskScore    = 100
         ErrorCode    = $ServiceLocations.ErrorCode
         ErrorMessage = $ServiceLocations.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("ServiceDLLLocations")) {
      $ServiceDLLLocations = Get-vlServiceDLLLocations
      $Output += [PSCustomObject]@{
         Name         = "Service.dll"
         DisplayName  = "Uncommon locations of service.dll"
         Description  = "Checks whether services use service.dll in uncommon locations"
         Score        = $ServiceDLLLocations.Score
         ResultData   = $ServiceDLLLocations.Result
         RiskScore    = 90
         ErrorCode    = $ServiceDLLLocations.ErrorCode
         ErrorMessage = $ServiceDLLLocations.ErrorMessage
      }
   }

   return $output
}

Write-Output (Get-vlWindowsServicesCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIFyAYJKoZIhvcNAQcCoIIFuTCCBbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDl7MF4QhFYsuVI
# BMaEq556LuNOvBHoG7sKG2OJjRyDYaCCAywwggMoMIICEKADAgECAhAV/4qQJS3s
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG2COOZdTmenoeY8tRy8HsiJNSWA+F9p
# 7fkH1q8YFJULMA0GCSqGSIb3DQEBAQUABIIBAD0RSc6OmfqYAM9HIm/fHt4r6kNJ
# W4vpWcXve4T2ZTQpF+J6iVBWdaXDn5aj4P4gNzLzyhk4doEUV9AxFnjPxaAmfql/
# S3vBrJFwuKAXc4nH6u1DBIuCbAnCzZXlaEfP54qN+GbuTqOz3rlOUe9gSI3yMJNy
# R4gsD4fzrc5msdBgD1UMSJzI/tqnlMvlrxE8rHhU6VPOrGI/AFvxHycLGQLbNWQa
# KPNEGAumCewdtGoqhLZre8m1WrvnSN9DHXDf8mbygg8FLiIvTL0T2aDOEbeY+NzF
# 4Bjp/fKHTD7GfBLRkvooyHYPAsY9CLfrxDJPVXnJV38yNz5Euwz+LZvljgI=
# SIG # End signature block
