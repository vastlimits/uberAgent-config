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
            Domain = $firewall | where-object { $_.Profile -eq "Domain" } | select-object -ExpandProperty Enabled
            Private = $firewall | where-object { $_.Profile -eq "Private" } | select-object -ExpandProperty Enabled
            Public = $firewall | where-object { $_.Profile -eq "Public" } | select-object -ExpandProperty Enabled
        }

        $score = 10

        if($result.Domain -eq $false -or $result.Private -eq $false) {
            $score = 5
        }

        if($result.Public -eq $false) {
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
    $rules = $rules | where-object { $_.ApplicationName -ne $null -or $_.ServiceName -ne $null  -or $_localPorts -ne $null -or $_.RemotePorts -ne $null }

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

    if ($params.Contains("all") -or $params.Contains("state")) {
        $firewallEnabled = Get-vlIsFirewallEnabled    
        $Output += [PSCustomObject]@{
            Name       = "Firewall - state"
            Score      = $firewallEnabled.Score
            ResultData = $firewallEnabled.Result
            RiskScore  = 100
            ErrorCode      = $firewallEnabled.ErrorCode
            ErrorMessage   = $firewallEnabled.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("openPorts")) {
        $openPorts = Get-vlOpenFirewallPorts
        $Output += [PSCustomObject]@{
            Name       = "Firewall - openPorts"
            Score      = $openPorts.Score
            ResultData = $openPorts.Result
            RiskScore  = 70
            ErrorCode      = $openPorts.ErrorCode
            ErrorMessage   = $openPorts.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("listeningPorts")) {
        $listeningPorts = Get-vlListeningPorts
        $Output += [PSCustomObject]@{
            Name       = "Firewall - listeningPorts"
            Score      = $listeningPorts.Score
            ResultData = $listeningPorts.Result
            RiskScore  = 50
            ErrorCode      = $listeningPorts.ErrorCode
            ErrorMessage   = $listeningPorts.ErrorMessage
        }
    }

    return $output
}

Write-Output (Get-vlFirewallCheck | ConvertTo-Json -Compress)