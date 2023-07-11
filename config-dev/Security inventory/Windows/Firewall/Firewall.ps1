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

   $riskScore = 100

   try {
      $privateNetwork = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq "Private" }
      $publicNetwork = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq "Public" }
      $domainAuthenticatedNetwork = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq "DomainAuthenticated" }

      $firewall = Get-NetFirewallProfile -All
      $result = [PSCustomObject]@{
         Domain  = [PSCustomObject]@{
            Enabled   = [bool]($firewall | where-object { $_.Profile -eq "Domain" } | select-object -ExpandProperty Enabled)
            Connected = if ($domainAuthenticatedNetwork) { $true } else { $false }
         }
         Private = [PSCustomObject]@{
            Enabled   = [bool]($firewall | where-object { $_.Profile -eq "Private" } | select-object -ExpandProperty Enabled)
            Connected = if ($privateNetwork) { $true } else { $false }
         }
         Public  = [PSCustomObject]@{
            Enabled   = [bool]($firewall | where-object { $_.Profile -eq "Public" } | select-object -ExpandProperty Enabled)
            Connected = if ($publicNetwork) { $true } else { $false }
         }
      }

      $score = 10

      if ($result.Domain.Enabled -eq $false -or $result.Private.Enabled -eq $false) {
         $score = 5
      }

      if ($result.Public.Enabled -eq $false) {
         $score = 0
      }

      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject($_)
   }
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

   $riskScore = 70

   try {
      $rulesEx = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue -PolicyStore ActiveStore
      $rulesSystemDefaults = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue -PolicyStore SystemDefaults
      $rulesStaticServiceStore = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue -PolicyStore StaticServiceStore

      $rulesEx = $rulesEx | Where-Object { $_.ID -notin $rulesSystemDefaults.ID }
      $rulesEx = $rulesEx | Where-Object { $_.ID -notin $rulesStaticServiceStore.ID }

      # microsoft uses the group property to identify rules that are created by default
      $rulesEx = $rulesEx | Where-Object { $_.Group -eq "" -or $null -eq $_.Group }

      $rulesEx = $rulesEx | ForEach-Object {
         $rule = $_
         $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
         $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule

         [PSCustomObject]@{
            Name              = $rule.Name
            DisplayName       = $rule.DisplayName
            ApplicationName   = $appFilter.Program
            LocalPorts        = $portFilter.LocalPort
            RemotePorts       = $portFilter.RemotePort
            Protocol          = $portFilter.Protocol
            Group             = $rule.Group
            Profile           = $rule.Profile
            PolicyStoreSource = $rule.PolicyStoreSource
         }
      }

      if ($null -eq $rulesEx) {
         $rulesEx = @()
      }

      return New-vlResultObject -result $rulesEx -score 10 -riskScore $riskScore
   }
   catch [Microsoft.Management.Infrastructure.CimException] {
      return "[Get-vlOpenFirewallPorts] You need elevated privileges"
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
         Description  = "This test verifies whether the Windows Defender Firewall is enabled or disabled. It also provides the current connection status of the network profiles. Network profiles allow the system to apply different firewall settings based on the network location, such as a public Wi-Fi network (Public), a corporate network (Domain), or a home network (Private)."
         Score        = $firewallEnabled.Score
         ResultData   = $firewallEnabled.Result
         RiskScore    = $firewallEnabled.RiskScore
         ErrorCode    = $firewallEnabled.ErrorCode
         ErrorMessage = $firewallEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("FWPorts")) {
      $openPorts = Get-vlOpenFirewallPorts
      $Output += [PSCustomObject]@{
         Name         = "FWPorts"
         DisplayName  = "Open firewall ports"
         Description  = "This test evaluates the presence of open inbound firewall rules on the system and provides a list of open ports. Open ports are entry points and can expose the system to unauthorized access. Rules marked as default are filtered out."
         Score        = $openPorts.Score
         ResultData   = $openPorts.Result
         RiskScore    = $openPorts.RiskScore
         ErrorCode    = $openPorts.ErrorCode
         ErrorMessage = $openPorts.ErrorMessage
      }
   }

   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-vlFirewallCheck | ConvertTo-Json -Compress)
