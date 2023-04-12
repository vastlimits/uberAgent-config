#Requires -RunAsAdministrator
#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

[Flags()] enum FW_PROFILE {
   Domain = 1
   Private = 2
   Public = 4
}

[Flags()] enum FW_IP_PROTOCOL_TCP {
   TCP = 6
   UDP = 17
   ICMPv4 = 1
   ICMPv6 = 58
}

[Flags()] enum FW_RULE_DIRECTION {
   IN = 1
   OUT = 2
}

[Flags()] enum FW_ACTION {
   BLOCK = 0
   ALLOW = 1
}


# function to check if firewall is enabled
function Get-vlIsFirewallEnabled {
   <#
    .SYNOPSIS
        Function that checks if the firewall is enabled.
    .DESCRIPTION
        Function that checks if the firewall is enabled.
    .LINK
        https://uberagent.com
    .OUTPUTS
        Returns a [psobject] containing the following properties:

        Domain
        Private
        Public

        The value of each property is a boolean indicating if the firewall is enabled for the specific profile.

    .EXAMPLE
        Get-vlIsFirewallEnabled
    #>

   try {
      $firewall = Get-NetFirewallProfile -All
      $result = [PSCustomObject]@{
         Domain  = $firewall | where-object { $_.Profile -eq "Domain" } | select-object -ExpandProperty Enabled
         Private = $firewall | where-object { $_.Profile -eq "Private" } | select-object -ExpandProperty Enabled
         Public  = $firewall | where-object { $_.Profile -eq "Public" } | select-object -ExpandProperty Enabled
      }

      $score = 10

      if ($result.Domain -eq $false -or $result.Private -eq $false) {
         $score = 5
      }

      if ($result.Public -eq $false) {
         $score = 0
      }

      return New-vlResultObject -result $result -score $score
   }
   catch {
      return New-vlErrorObject($_)
   }
}

Function Get-vlEnabledRules {
   <#
    .SYNOPSIS
        Function that returns all enabled rules for a specific profile.
    .DESCRIPTION
        Function that returns all enabled rules for a specific profile.
    .LINK
        https://uberagent.com
    .NOTES
        This function is used by Get-vlOpenFirewallPorts. The results are filtered by the following properties:
        Enabled = true
        Profiles = $profile
        Direction = IN
        Action = ALLOW
        ApplicationName or ServiceName or LocalPort or RemotePort = not null

    .OUTPUTS
        Returns an array of objects containing the following properties:

        Name
        ApplicationName
        LocalPorts
        RemotePorts

    .EXAMPLE
        Get-vlEnabledRules
    #>

   Param($profile)
   $rules = (New-Object -comObject HNetCfg.FwPolicy2).rules
   $rules = $rules | where-object { $_.Enabled -eq $true }
   $rules = $rules | where-object { $_.Profiles -bAND $profile }
   $rules = $rules | where-object { $_.Direction -bAND [FW_RULE_DIRECTION]::IN }
   $rules = $rules | where-object { $_.Action -bAND [FW_ACTION]::ALLOW }
   $rules = $rules | where-object { $_.ApplicationName -ne $null -or $_.ServiceName -ne $null -or $_localPorts -ne $null -or $_.RemotePorts -ne $null }

   #remove every property excepted Name, ApplicationName and LocalPorts and RemotePorts
   $rules = $rules | select-object -Property Name, ApplicationName, LocalPorts, RemotePorts

   return $rules
}

# function to check open firewall ports returns array of open ports
function Get-vlOpenFirewallPorts {
   <#
    .SYNOPSIS
        Function that iterates over all profiles and returns all enabled rules for all profiles.
    .DESCRIPTION
        Function that iterates over all profiles and returns all enabled rules for all profiles.
    .LINK
        https://uberagent.com

    .OUTPUTS
        Returns an array of objects containing the following properties:

        Name
        ApplicationName
        LocalPorts
        RemotePorts

    .EXAMPLE
        Get-vlOpenFirewallPorts
    #>

   try {
      $openPorts = [FW_PROFILE].GetEnumNames() | ForEach-Object { Get-vlEnabledRules -profile ([FW_PROFILE]::$_) }

      return New-vlResultObject -result $openPorts -score 10
   }
   catch [Microsoft.Management.Infrastructure.CimException] {
      return "[Get-vlOpenFirewallPorts] You need elevated privileges"
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlListeningPorts {
   <#
    .SYNOPSIS
        Function that returns all listening ports.
    .DESCRIPTION
        Function that returns all listening ports.
    .LINK
        https://uberagent.com

    .OUTPUTS
        Returns an array of objects containing the following properties:

        LocalAddress
        LocalPort
        OwningProcess
        OwningProcessName
        OwningProcessPath

    .EXAMPLE
        Get-vlListeningPorts
    #>

   try {
      $listenApps = Get-NetTCPConnection -State Listen

      # use $listenApps and get local port, local address, process name
      $listeningPorts = $listenApps | select-object -Property LocalAddress, LocalPort, OwningProcess, OwningProcessName, OwningProcessPath

      # use $openPorts and find out the name of the OwningProcess id and add it to the object as OwningProcessName and OwningProcessPath
      $listeningPorts | ForEach-Object {
         $process = Get-Process -Id $_.OwningProcess
         $_.OwningProcessName = $process.Name
         $_.OwningProcessPath = $process.Path
      }

      return New-vlResultObject -result $listeningPorts -score 10
   }
   catch [Microsoft.Management.Infrastructure.CimException] {
      return "[Get-vlListeningPorts] You need elevated privileges"
   }
   catch {
      return New-vlErrorObject($_)
   }
}


function Get-vlFirewallCheck {
   <#
    .SYNOPSIS
        Function that performs the Firewall check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the Firewall check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlFirewallCheck
    #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("FWState")) {
      $firewallEnabled = Get-vlIsFirewallEnabled
      $Output += [PSCustomObject]@{
         Name         = "FWState"
         DisplayName  = "Firewall status"
         Description  = "Checks if the firewall is enabled."
         Score        = $firewallEnabled.Score
         ResultData   = $firewallEnabled.Result
         RiskScore    = 100
         ErrorCode    = $firewallEnabled.ErrorCode
         ErrorMessage = $firewallEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("FWPorts")) {
      $openPorts = Get-vlOpenFirewallPorts
      $Output += [PSCustomObject]@{
         Name         = "FWPorts"
         DisplayName  = "Open firewall ports"
         Description  = "Checks if there are open firewall ports and returns the list of open ports."
         Score        = $openPorts.Score
         ResultData   = $openPorts.Result
         RiskScore    = 70
         ErrorCode    = $openPorts.ErrorCode
         ErrorMessage = $openPorts.ErrorMessage
      }
   }

   <#
    Disabled for now, because a port can have the status LISTENING and still be blocked by the firewall.
    if ($params.Contains("all") -or $params.Contains("FWListPorts")) {
        $listeningPorts = Get-vlListeningPorts
        $Output += [PSCustomObject]@{
            Name       = "FWListPorts"
            DisplayName  = "Listening Firewall Ports"
            Description  = "Checks if there are ports with the status LISTENING and returns the list of listening ports."
            Score      = $listeningPorts.Score
            ResultData = $listeningPorts.Result
            RiskScore  = 50
            ErrorCode      = $listeningPorts.ErrorCode
            ErrorMessage   = $listeningPorts.ErrorMessage
        }
    }
    #>

   return $output
}

Write-Output (Get-vlFirewallCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIFyAYJKoZIhvcNAQcCoIIFuTCCBbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCRQ2xxsBdnCrnh
# Ni9PoKpi1PQ+qWUreT456dPK9dKBZ6CCAywwggMoMIICEKADAgECAhAV/4qQJS3s
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPGd09qhb6bi3BkF5ZL5EkLmPxP7t1pL
# 89lz4uXrY2qYMA0GCSqGSIb3DQEBAQUABIIBAG/QizozrVUO99hykRuPtJNfTAMG
# wBqMmW1CMGkMd5Qz5cullHj3UbRi3z9pEQAmm7be6je93OgJ7jRdy5dlo6S9l0XO
# hoUoMn+aSSaLWCFuID3+hEhytniWaKY/83MWBVOW6d1L0d1LJia4yFLmeJlThWF6
# 9C4CTJKqZ0sw9u6vzIkA0pqG2QV1C/nHtLr4wHBIkJQoxGk/iPFh/Qqb+TC7z2CR
# ayPJssbzWYKTGOS79gY543zNmkkwPrIg3/hsaJm1MwLtEXswtgUto8mv3bq5JQJh
# beli4XWPi8WVu3V2TFH8lgJGhk5y1AZqrQOc9GR4mxNZPuUF9zbwWitP62o=
# SIG # End signature block
