#Requires -RunAsAdministrator
#Requires -Version 3.0

. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#https://mcpforlife.com/2020/04/14/how-to-resolve-this-state-value-of-av-providers/
[Flags()] enum ProductState {
   Off = 0x0000
   On = 0x1000
   Snoozed = 0x2000
   Expired = 0x3000
}

[Flags()] enum SignatureStatus {
   UpToDate = 0x00
   OutOfDate = 0x10
}

[Flags()] enum ProductOwner {
   NonMs = 0x000
   Windows = 0x100
}

[Flags()] enum ProductFlags {
   SignatureStatus = 0x000000F0
   ProductOwner = 0x00000F00
   ProductState = 0x0000F000
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

   param (

   )

   process {
      try {
         $instances = Get-CimInstance -ClassName AntiVirusProduct -Namespace "root\SecurityCenter2"

         $riskScore = 100
         $score = 0
         $result = @()
         $avEnabledFound = $false

         foreach ($instance in $instances) {
            $avEnabled = $([ProductState]::On.value__ -eq $($instance.productState -band [ProductFlags]::ProductState) )
            $avUp2Date = $([SignatureStatus]::UpToDate.value__ -eq $($instance.productState -band [ProductFlags]::SignatureStatus) )

            if ($avEnabled) {
               $avEnabledFound = $true
               if ($avUp2Date) {
                  $score = 10
               }
               else {
                  $score = 4
               }
            }

            $result += [PSCustomObject]@{
               AntivirusEnabled  = $avEnabled
               AntivirusName     = $instance.displayName
               AntivirusUpToDate = $avUp2Date
            }
         }

         if (-not $avEnabledFound) {
            $score = 0
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
      catch {
         return New-vlErrorObject($_)
      }
      finally {

      }

   }

}


function Get-vlDefenderStatus {
   <#
    .SYNOPSIS
        Get the status of the registrated antivirus
    .DESCRIPTION
        Get the status of the registrated antivirus using Get-MpComputerStatus from the Microsoft Antimalware API
    .NOTES
        The result will be converted to JSON and returend as a vlResultObject or vlErrorObject
        Requires min PowerShell 3.0 and the Microsoft Antimalware API
    .LINK
        https://uberagent.com
    .OUTPUTS
        A vlResultObject | vlErrorObject [psobject] containing the list of AMSI providers
    .EXAMPLE
        Get-vlDefenderStatus
    #>

   [CmdletBinding()]
   param (

   )

   process {
      try {
         $instances = Get-MpComputerStatus

         $result = [PSCustomObject]@{
            AMEngineVersion                 = $instances.AMEngineVersion
            AMServiceEnabled                = $instances.AMServiceEnabled
            AMServiceVersion                = $instances.AMServiceVersion
            AntispywareEnabled              = $instances.AntispywareEnabled
            AntivirusEnabled                = $instances.AntivirusEnabled
            AntispywareSignatureLastUpdated = $instances.AntispywareSignatureLastUpdated
            AntispywareSignatureVersion     = $instances.AntispywareSignatureVersion
            AntivirusSignatureLastUpdated   = $instances.AntivirusSignatureLastUpdated
            QuickScanSignatureVersion       = $instances.QuickScanSignatureVersion
         }

         return New-vlResultObject -result $result
      }
      catch {
         return New-vlErrorObject($_)
      }
      finally {

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
         Description  = "Checks if the antivirus is enabled and up to date."
         Score        = $avStatus.Score
         ResultData   = $avStatus.Result
         RiskScore    = $avStatus.RiskScore
         ErrorCode    = $avStatus.ErrorCode
         ErrorMessage = $avStatus.ErrorMessage
      }
   }

   <#
    if ($params.Contains("all") -or $params.Contains("AVDefStat")) {
        $defenderStatus = Get-vlDefenderStatus
        $Output += [PSCustomObject]@{
            Name       = "AVDefStat"
            DisplayName  = "Defender status"
            Description  = "Checks if the defender is enabled and up to date."
            Score      = 0
            ResultData = $defenderStatus.Result
            RiskScore  = 100
            ErrorCode      = $defenderStatus.ErrorCode
            ErrorMessage   = $defenderStatus.ErrorMessage
        }
    }
    #>

   Write-Output $output
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlAntivirusCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIFyAYJKoZIhvcNAQcCoIIFuTCCBbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBHFPQajsz2nCaA
# UqjCq8Mp1EDLxdQ8OgqLj52DLO9pwaCCAywwggMoMIICEKADAgECAhAV/4qQJS3s
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII1frh2EgBmWETvhrjCeMprfUZiTRktd
# MXaE5fZFrOAtMA0GCSqGSIb3DQEBAQUABIIBABWknIpM0TylbYXyuvElh+1HCsCb
# +2yaGYAJpSHx374jMZjrvlOkRMSOWBuG0+1jXdBoKlxlOssV32/9Wx/FK2I4J4zx
# +BjhYBtwIskWt4IR7CMAfDHiCT3c8MinGCCHB+Ev6GyzgUdAGL0Guv3ZrEQWwjei
# TfIpYbICPVqVATQoWZF7tqYb6kUpXtg/eQ3WH4DTMyrDRRjiKsy9ZnYXa9xPMl/z
# 1XTKA7gdDYWum+LdnbhR+iQQqdZSNbE4NzN7T+3IsVUvc9ZVbF3Rkr/I1pK+08py
# 0xIfriH3CozGW59w+XQJUN4wHJOPOtRGHtnm3BH1aZmvLfrgqSduK2M2+lc=
# SIG # End signature block
