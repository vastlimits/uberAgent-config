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

      $SMBv1 = $false

      if (Test-Path HKLM:\SYSTEM\CurrentControlSet\services\mrxsmb10) {
         $mrxsmb10 = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\services\mrxsmb10" -Value "Start"
         $LanmanWorkstation = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Value "DependOnService"

         if ($mrxsmb10 -ne 4 -and $LanmanWorkstation -icontains "mrxsmb10") {
            $SMBv1 = $true
         }
      }

      if ($SMBv1 -eq $false) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # SMBv1 is disabled
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # SMBv1 is enabled
         return New-vlResultObject -result $result -score 2
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
            return New-vlResultObject -result $result -score 10
         }
         elseif ($SMBSigningRequired -eq 0 -and $SMBSigningEnabled -eq 1) {
            $result = [PSCustomObject]@{
               state = "Enabled"
            }
            # SMB signing is enabled but not required
            return New-vlResultObject -result $result -score 2
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2
         }
      }
      elseif ($SMBv1.Result -like '*false*') {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"

         if ($SMBSigningRequired -eq 1) {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2
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
      if ((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object -Property 'TcpipNetbiosOptions' -eq 1).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # NetBIOS is disabled
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # NetBIOS is enabled
         return New-vlResultObject -result $result -score 3
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
      if (((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter IPEnabled=TRUE | Where-Object -Property 'WINSPrimaryServer' -ne $null).ServiceName).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # WINS is not in usage
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # WINS is in usage
         return New-vlResultObject -result $result -score 3
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationSSLTLS {
   <#
   .SYNOPSIS
       Checks whether outdated SSL and TLS versions are enabled
   .DESCRIPTION
       Checks whether outdated SSL and TLS versions are enabled
   .OUTPUTS
       If outdated SSL and TLS versions are disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
       If outdated SSL and TLS versions are enabled, the function returns a PSCustomObject with the protocols in use
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationSSLTLS
   #>

   try {

      $Protocols = @("TLS 1.0", "TLS 1.1", "SSL 2.0", "SSL 3.0")
      $ProtocolsInUse = @()
      foreach ($Protocol in $Protocols) {
         $null = $Enabled
         $null = $DisabledByDefault

         if (test-path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client") {
            $Enabled = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Value "Enabled"
            $DisabledByDefault = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Value "DisabledByDefault"

            if ($Enabled -eq 1 -OR $DisabledByDefault -eq 0) {
               $ProtocolsInUse += $Protocol
            }
         }
         else {
            $ProtocolsInUse += $Protocol
         }
      }



      if ($ProtocolsInUse.Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # Outdated protocols are disabled
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $ProtocolsInUse
         }
         # Outdated protocols are enabled
         return New-vlResultObject -result $result -score 2
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
         RiskScore    = 100
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
         RiskScore    = 40
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
         RiskScore    = 20
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
         RiskScore    = 20
         ErrorCode    = $WINS.ErrorCode
         ErrorMessage = $WINS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCSSLTLS")) {
      $SSLTLS = Get-vlNetworkConfigurationSSLTLS
      $Output += [PSCustomObject]@{
         Name         = "NCSSLTLS"
         DisplayName  = "Network configuration SSL/TLS"
         Description  = "Checks whether outdated SSL and TLS versions are enabled."
         Score        = $SSLTLS.Score
         ResultData   = $SSLTLS.Result
         RiskScore    = 40
         ErrorCode    = $SSLTLS.ErrorCode
         ErrorMessage = $SSLTLS.ErrorMessage
      }
   }


   return $output
}

Write-Output (Get-vlNetworkConfigurationCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIFyAYJKoZIhvcNAQcCoIIFuTCCBbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCmjUv5zOJbgJVc
# rFmj/B4AcFTrN6Q8fY3QTWbCTad2rqCCAywwggMoMIICEKADAgECAhAV/4qQJS3s
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICS/YHEV3BZnFsbcLY8kkRGChGXJQtOb
# OC5QIeQZz1xoMA0GCSqGSIb3DQEBAQUABIIBAECQcFNx/7cq3d0dQBH7amKZe4t2
# AsJEIQvCy4wmYBbYWvBYi8mAEmhJPpaUlyqFV6tXNMRKIYME+/IRmNIXs0T6NlyI
# a0rEUTnhX+s1OdqfCOhcuxHTjK+OiB9auK0BoR23ppnLXEFM3YutXFQlSL8KQymQ
# xKRMpz7Jiaf78y54+K0pPfrEk5Mke9PeBc0SdiqEmb6hocy/F7Gb82Xm6AYxFbvw
# 9B/XSTJfc9JBkKKbvHrOPq4/NVqqb8gR77b6HdQ21EtgMo55O/P8r3W87bATlTS7
# 0cQdaixO6ysTjfJu4m1G7o4Hp1K3uCvbvu77NzioefzKLaXFkEu053Vpyus=
# SIG # End signature block
