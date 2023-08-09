#Requires -RunAsAdministrator
#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

$FW_PROTOCOL = @{
   ICMPv4 = 1
   TCP    = 6
   UDP    = 17
   ICMPv6 = 58
   ALL    = 256
}

$FW_RULE_DIRECTION = @{
   IN  = 1
   OUT = 2
}

$FW_ACTION = @{
   BLOCK = 0
   ALLOW = 1
}

$FW_PROFILES = @{
   Domain  = 1
   Private = 2
   Public  = 4
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
      $isWindows7 = Get-vlIsWindows7

      if ($isWindows7 -eq $true) {

         $networkListManager = [System.Activator]::CreateInstance([System.Type]::GetTypeFromCLSID("DCB00C01-570F-4A9B-8D69-199FDBA5723B"))

         $connectionStatus = @()
         $networks = $networkListManager.GetNetworks(1)

         foreach ($network in $networks) {
            $netCat = $network.GetCategory()

            if ($netCat -eq 0) {
               $connectionStatus += "Public"
            }
            elseif ($netCat -eq 1) {
               $connectionStatus += "Private"
            }
            elseif ($netCat -eq 2) {
               $connectionStatus += "Domain"
            }
         }

         # Create a new instance of the HNetCfg.FwPolicy2 object
         $fwPolicy2 = New-Object -ComObject HNetCfg.FwPolicy2

         $result = [PSCustomObject]@()

         $domainStatus = [bool]($fwPolicy2.FirewallEnabled(1))
         $privateStatus = [bool]($fwPolicy2.FirewallEnabled(2))
         $publicStatus = [bool]($fwPolicy2.FirewallEnabled(4))

         $result += [PSCustomObject]@{
            Profile   = "Domain"
            Enabled   = $domainStatus
            Connected = if ($connectionStatus -contains "Domain") { $true } else { $false }
         }
         $result += [PSCustomObject]@{
            Profile   = "Private"
            Enabled   = $privateStatus
            Connected = if ($connectionStatus -contains "Private") { $true } else { $false }
         }
         $result += [PSCustomObject]@{
            Profile   = "Public"
            Enabled   = $publicStatus
            Connected = if ($connectionStatus -contains "Public") { $true } else { $false }
         }

         $score = 10

         if ($domainStatus -eq $false -or $privateStatus -eq $false) {
            $score = 5
         }

         if ($publicStatus -eq $false) {
            $score = 0
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore

      }
      else {
         $privateNetwork = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq "Private" }
         $publicNetwork = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq "Public" }
         $domainAuthenticatedNetwork = Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq "DomainAuthenticated" }

         $firewall = Get-NetFirewallProfile -All
         $result = [PSCustomObject]@()

         $domainStatus = [bool]($firewall | where-object { $_.Profile -eq "Domain" } | select-object -ExpandProperty Enabled)
         $privateStatus = [bool]($firewall | where-object { $_.Profile -eq "Private" } | select-object -ExpandProperty Enabled)
         $publicStatus = [bool]($firewall | where-object { $_.Profile -eq "Public" } | select-object -ExpandProperty Enabled)

         $result += [PSCustomObject]@{
            Profile   = "Domain"
            Enabled   = $domainStatus
            Connected = if ($domainAuthenticatedNetwork) { $true } else { $false }
         }
         $result += [PSCustomObject]@{
            Profile   = "Private"
            Enabled   = $privateStatus
            Connected = if ($privateNetwork) { $true } else { $false }
         }
         $result += [PSCustomObject]@{
            Profile   = "Public"
            Enabled   = $publicStatus
            Connected = if ($publicNetwork) { $true } else { $false }
         }

         $score = 10

         if ($domainStatus -eq $false -or $privateStatus -eq $false) {
            $score = 5
         }

         if ($publicStatus -eq $false) {
            $score = 0
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
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
      $isWindows7 = ((Get-vlIsWindows7) -eq $false)

      if ($isWindows7 -eq $true) {
         $fwPolicy2 = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("HNetCfg.FwPolicy2"))

         # Erhalte die Regeln
         $rules = $fwPolicy2.Rules

         $output = @()

         # Iteriere über die Regeln
         foreach ($rule in $rules) {
            if ($rule.Direction -eq $FW_RULE_DIRECTION["IN"] -and $rule.Action -eq $FW_ACTION["ALLOW"] -and $rule.Enabled -eq $true -and ($rule.Grouping -eq "" -or $null -eq $rule.Grouping) ) {

               $parsedProfile = ""
               $parsedProtocol = ""

               if ($null -ne $rule.Profiles) {
                  $parsedProfile = Get-vlHashTableKeys -hashTable $FW_PROFILES -value $rule.Profiles

                  if ($parsedProfile.length -eq 3) {
                     $parsedProfile = "Any"
                  }
                  else {
                     $parsedProfile = $parsedProfile -join ", "
                  }
               }

               if ($null -ne $rule.Profiles) {
                  $parsedProtocol = Get-vlHashTableKey -hashTable $FW_PROTOCOL -value $rule.Protocol
               }

               $output += [PSCustomObject]@{
                  Name            = if ($null -ne $rule.Name) { $rule.Name } else { "" }
                  DisplayName     = if ($null -ne $rule.Description) { $rule.Description } else { "" }
                  ApplicationName = if ($null -ne $rule.ApplicationName) { $rule.ApplicationName } else { "" }
                  LocalPorts      = if ($null -ne $rule.LocalPorts) { if ($rule.LocalPorts -eq "*") { "Any" } else { $rule.LocalPorts } } else { "" }
                  RemotePorts     = if ($null -ne $rule.RemotePorts) { if ($rule.RemotePorts -eq "*") { "Any" } else { $rule.RemotePorts } } else { "" }
                  Protocol        = if ($null -ne $rule.Protocol) { Convert-vlEnumToString $parsedProtocol } else { "" }
                  Profile         = if ($null -ne $parsedProfile) { Convert-vlEnumToString $parsedProfile } else { "" }
               }
            }
         }

         return New-vlResultObject -result $output -score 10 -riskScore $riskScore
      }
      else {
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
               Name                  = $rule.Name
               DisplayName           = $rule.DisplayName
               ApplicationName       = $appFilter.Program
               LocalPorts            = $portFilter.LocalPort
               RemotePorts           = $portFilter.RemotePort
               Protocol              = Convert-vlEnumToString $portFilter.Protocol
               Profile               = Convert-vlEnumToString $rule.Profile
               PolicyStoreSourceType = Convert-vlEnumToString $rule.PolicyStoreSourceType
            }
         }

         if ($null -eq $rulesEx) {
            $rulesEx = @()
         }

         return New-vlResultObject -result $rulesEx -score 10 -riskScore $riskScore
      }
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

   $isWindows7 = Get-vlIsWindows7

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

   if ($params.Contains("all") -or $params.Contains("FWPorts") -and $isWindows7 -eq $false) {
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

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


Write-Output (Get-vlFirewallCheck | ConvertTo-Json -Compress)
