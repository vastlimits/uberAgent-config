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
# MIIFowYJKoZIhvcNAQcCoIIFlDCCBZACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNR5LLVQeJW7DCNSmakDJXFOl
# XoGgggMsMIIDKDCCAhCgAwIBAgIQFf+KkCUt7J9Ay+NZ+dMpvjANBgkqhkiG9w0B
# AQsFADAsMSowKAYDVQQDDCFUZXN0IFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nIENl
# cnQwHhcNMjMwNDA2MDkwNDIzWhcNMjgwNDA2MDkxNDIzWjAsMSowKAYDVQQDDCFU
# ZXN0IFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nIENlcnQwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDGNh/YR7ouKwH6jZ90A3N+6hxgzWQQdoPchRC6CYYC
# iHL7KBDnY8ftWaq5Unre49YAQJzsNobxZi3S6xy+bdt2eBZyAaINYnLcgkoWlGeK
# OmCgoSxKH75Go55Tf1nhIw1mJZsafC6frv5M3EmVFI8frPSJK5X4w4z14qTsziz2
# gMxWvqaqgeIA+nMwvNGgN4e5seqLd00/RTMepNVwoBtnKFqXRPv1xocvfRQYB0Tr
# JIsFK3ztgBurNkaaaVM9jupH+53TI/7g7b0qVLIQ0qjLIaC8lpx5eE6mq2O66IpL
# SEBRTjad4idairpXuu8UtMQwbicIWn+tkDSjTeu5VlP5AgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUZkiDicEY
# 2vHryiFtS4lQTor6ci0wDQYJKoZIhvcNAQELBQADggEBAGLBwJy8i4BI/O63ID7h
# lrOdT3VOYPf29gFXZ4ldDLpY1/TJcPp53XTehWtO+Qztfy/nbCXWJsR8PR6djnTW
# 6lWQjXCP7N8DPiVU115Ha6D1mnyW9nGsOVeqd6doN9swXbSJ8VIi9Okv6IlDGYPS
# SvcbvnEz4BT1NmtMaY8ensTQm2FvAcjvFq09n89xoeJ0ifQ2t5NNhdRN1fY1J6OL
# NHyrmKGQ3dTJZDbiuQ9QNXx/G7J9ieZkduTh73wQRkCBM22Al4QzyMnbRg7wY4/X
# tzszEv4eV3Bg+RXMlTsCOP59AO2rCh02w/iSPQk/l3siVXT1bVW4tNvS15eWbcOk
# jDYxggHhMIIB3QIBATBAMCwxKjAoBgNVBAMMIVRlc3QgUG93ZXJTaGVsbCBDb2Rl
# IFNpZ25pbmcgQ2VydAIQFf+KkCUt7J9Ay+NZ+dMpvjAJBgUrDgMCGgUAoHgwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU
# ihW+6/kRuQNBevDHCbxaIpqrwbAwDQYJKoZIhvcNAQEBBQAEggEAS6kS5MiABFFR
# CKnWMVeKmrbtRVTrAFLIEOg32H+u3m7YTk5vacT9XZCZhZH5lR9sxEBVNdh3veBU
# e7fMNBOuWa3A92JkWJPZ+hDAWHNf6KtppudgXZ0oWMeKnUdJjA+jt0FeISlA/ilw
# 4YP5lVx1CIFldWOcMO+r99ueJp5fjvXq++73jxsKr0jq8bEAB+E+7Aeu+TAYg9IP
# 81NRRO0af77aZ+xOtLG8VLCGeWDNf9H96o354b7s6ZNRTc9nttaEIGBjCTStxp/W
# VTrhTUNnpkpi/4IRrAtzP9yShwUrB7gJRIedbgXVOTYrX4QAvQi6PNecUohhDx1i
# rFgp9RRehQ==
# SIG # End signature block
