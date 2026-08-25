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

function Get-vlIsFirewallEnabled_COM {
   <#
    .SYNOPSIS
        Function that checks if the firewall is enabled using the COM Interface
    .DESCRIPTION
        Function that checks if the firewall is enabled using the COM Interface
    .OUTPUTS
        Returns a [psobject] containing the following properties:

        Domain
        Private
        Public

        The value of each property is a boolean indicating if the firewall is enabled for the specific profile.

    .EXAMPLE
        Get-vlIsFirewallEnabled_COM
    #>

   $riskScore = 100

   try {
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
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlIsFirewallEnabled {
   <#
    .SYNOPSIS
        Function that checks if the firewall is enabled.
    .DESCRIPTION
        Function that checks if the firewall is enabled.
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
      $isNetConnectionProfileAvailable = Get-vlIsCmdletAvailable "Get-NetConnectionProfile"
      $isNetFirewallProfile = Get-vlIsCmdletAvailable "Get-NetFirewallProfile"

      if ($isNetConnectionProfileAvailable -eq $false -or $isNetFirewallProfile -eq $false) {
         return Get-vlIsFirewallEnabled_COM
      }
      else {
         $netConnectionProfile = Get-NetConnectionProfile -ErrorAction Stop
         $privateNetwork = $netConnectionProfile | Where-Object { $_.NetworkCategory -eq "Private" }
         $publicNetwork = $netConnectionProfile | Where-Object { $_.NetworkCategory -eq "Public" }
         $domainAuthenticatedNetwork = $netConnectionProfile | Where-Object { $_.NetworkCategory -eq "DomainAuthenticated" }

         $firewall = Get-NetFirewallProfile -All -PolicyStore ActiveStore -ErrorAction Stop
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
      # If Get-NetConnectionProfile is not working as expected, for example because the Wmi-Class is not available, we fall back to the com interface
      return (Get-vlIsFirewallEnabled_COM)
   }
}

function Get-vlOpenFirewallPorts_COM {
   <#
    .SYNOPSIS
        Function that iterates over all profiles and returns all enabled rules for all profiles using COM Interface.
    .DESCRIPTION
        Function that iterates over all profiles and returns all enabled rules for all profiles using COM Interface.
    .LINK
        https://uberagent.com

    .OUTPUTS
        Returns an array of objects containing the following properties:

        Name
        ApplicationName
        LocalPorts
        RemotePorts

    .EXAMPLE
        Get-vlOpenFirewallPorts_COM
    #>

   $riskScore = 70

   try {
      $fwPolicy2 = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("HNetCfg.FwPolicy2"))

      $rules = $fwPolicy2.Rules
      $output = @()

      foreach ($rule in $rules) {
         if ($rule.Direction -eq $FW_RULE_DIRECTION["IN"] -and $rule.Action -eq $FW_ACTION["ALLOW"] -and $rule.Enabled -eq $true -and ($rule.Grouping -eq "" -or $null -eq $rule.Grouping) ) {

            $parsedProfile = ""
            $parsedProtocol = ""

            if ($null -ne $rule.Profiles) {
               $parsedProfile = Get-vlHashTableKeys -hashTable $FW_PROFILES -value $rule.Profiles

               if ($null -ne $parsedProfile -and $parsedProfile.length -eq 3) {
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
   catch {
      return New-vlErrorObject -context $_
   }
}

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
      $isGetNetFirewallRuleAvailable = Get-vlIsCmdletAvailable "Get-NetFirewallRule"
      $isGetNetFirewallPortFilter = Get-vlIsCmdletAvailable "Get-NetFirewallPortFilter"
      $isNetFirewallApplicationFilter = Get-vlIsCmdletAvailable "Get-NetFirewallApplicationFilter"

      if ($isGetNetFirewallRuleAvailable -eq $false -or $isGetNetFirewallPortFilter -eq $false -or $isNetFirewallApplicationFilter -eq $false) {
         # Get-NetFirewallRule are not available
         return Get-vlOpenFirewallPorts_COM
      }
      else {
         $rulesEx = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop -PolicyStore ActiveStore
         $rulesSystemDefaults = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop -PolicyStore SystemDefaults
         $rulesStaticServiceStore = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop -PolicyStore StaticServiceStore

         $rulesEx = $rulesEx | Where-Object { $_.ID -notin $rulesSystemDefaults.ID }
         $rulesEx = $rulesEx | Where-Object { $_.ID -notin $rulesStaticServiceStore.ID }

         # microsoft uses the group property to identify rules that are created by default
         $rulesEx = $rulesEx | Where-Object { $_.Group -eq "" -or $null -eq $_.Group }

         $rulesEx = $rulesEx | ForEach-Object {
            $rule = $_
            $portFilter = Get-NetFirewallPortFilter -PolicyStore ActiveStore -AssociatedNetFirewallRule $rule -ErrorAction Stop
            $appFilter = Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -AssociatedNetFirewallRule $rule -ErrorAction Stop

            $localPorts = if ($portFilter.LocalPort -is [System.Collections.IEnumerable] -and $portFilter.LocalPort -isnot [string]) {
               $portFilter.LocalPort -join ','
            }
            else {
               $portFilter.LocalPort
            }

            $remotePorts = if ($portFilter.RemotePort -is [System.Collections.IEnumerable] -and $portFilter.RemotePort -isnot [string]) {
               $portFilter.RemotePort -join ','
            }
            else {
               $portFilter.RemotePort
            }

            [PSCustomObject]@{
               Name                  = $rule.Name
               DisplayName           = $rule.DisplayName
               ApplicationName       = $appFilter.Program
               LocalPorts            = $localPorts
               RemotePorts           = $remotePorts
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
   catch {
      # try to use the com interface if there was an exception
      return (Get-vlOpenFirewallPorts_COM)
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
         Description  = "Windows: This test verifies whether the Windows Defender Firewall is enabled or disabled. It also provides the current connection status of the network profiles. Network profiles allow the system to apply different firewall settings based on the network location, such as a public Wi-Fi network (Public), a corporate network (Domain), or a home network (Private). macOS: performs comprehensive checking of firewall settings. If the firewall is enabled, this test also validates the status of the block-all rule, stealth mode, and a list of approved applications."
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

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


Write-Output (Get-vlFirewallCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIooQYJKoZIhvcNAQcCoIIokjCCKI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBSwhg6M4j9WDLx
# qeuiitNIexvrvTwu27MgpK7EZ0qLMKCCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggcBMIIE6aADAgECAhAP47Ki0imEqa3MI1tkbzHeMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE0MDAwMDAwWhcNMjcwNTEz
# MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0Zsb3JpZGExGDAWBgNV
# BAcTD0ZvcnQgTGF1ZGVyZGFsZTEdMBsGA1UEChMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4xDzANBgNVBAsTBkNpdHJpeDEdMBsGA1UEAxMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDWvV/OH9/sYPfeiQAh
# eDNU6vKMQlp+6UDbpI629yfSkJFN8YHaKLwTBL7o8njOMKdbFOSC1LwWh04pGV0Z
# DoCwXTOmzvXm10J2D6a6FKt6mZSKpwzI9RHbU8r26rhU0YU3ikAVDjTwHj44QHeL
# 0znzOlAAxzglEvpCOjHmluKMmaGqFtMdshrC4JPHjSS3Ksy2CSt5zNV88eEoU51v
# MsV/mN7wwnS8pfvFX+1J0dbHxcizG8HAeP66DG9Sedi1Tzm9beBcgYR4IMLXEe6B
# ac2y1AhOc+qFAWhj7ayMy3Mhxk4EZbXVGDP3n+GjiBUnWEfFu3DSucBi6uID+d/r
# 1mkT00hADT/aC2eT/Q/DEm+zVEuOQduX0YmBSe3anfTVLcDieVw/pI60U/e/4L8p
# JDgDwDziLIFKogXRtQYnV9fn3PqMisEigo22HCU6ieJq2lkPb6AZhdSjgFEz242t
# uDwfstvbn6tiZUXa6HggVbPZVZXTUFKhBsC8WE7VdNVd2HECAwEAAaOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBRbcl4N
# sqHrugpyuVoA9I4eak86SjA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAba1In5WIqLU6LE1uLOVwCllMLOAVeWUb1wPJ2fugaH891Oy42VUvND/cxd2L
# Fl8aIBEn9snnxJpFlyoLG3eNZYPLvSHgFuWlBlHkp4cwL4hihgjXQvRdhKFINE87
# 7RCLg9aNh8LzxNs9ciMM/sho/+dv2cojZPBqCZBxL9Fk+irRkZNUwgtR6/F2ijMu
# BnbGI9M24J6QqGj81wOSIrldQ/6hFGhDG0h58VZ+s8W0Bl4gf6P7lxZb8t0biBD5
# uijZxf9Ny4grACnIY9YQQRAH9k4QcBofNvro4U20OQIjRP7i7acQ5+SyFBzIn5Ko
# MkspCGz8VkvefMDgj91dXJSBBZlWIPRkRRETTbZhq83zjZNeupLCDMGJg1hUvtOu
# Is+Wn3+1/K5jrBK9dW3BukExwO/HpumRJ5T3gCPeCz8015XXsvixZSJPW91U1zwt
# +srK0tvNKBIPGSaVfJkLsf5iKeTQVCZtR8Y17ZNX0rLU3DeBytc3d3jfafqeVlih
# YrCTmQp9FiL9gzlr4OxVghgP6mCki7B/0SJXGg+tR1AOp12T5h/FSelSoPgECFhn
# aWQct57F/q6gSrTxVxwm1/xjb2EehEriH0H+TSJ+Jhu+z4y/Slc3qzt3haC8GjEU
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxgho+MIIaOgIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggZgw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLAYKKwYBBAGCNwIBDDEeMBygGoAYAEYAaQByAGUAdwBhAGwAbAAu
# AHAAcwAxMC8GCSqGSIb3DQEJBDEiBCAwGxo7A0Ts/VMaxWBTsJfJ+pcRWf+Zlk51
# Ch7YXJn5izANBgkqhkiG9w0BAQEFAASCAYDUuaHfYKT99mIxe4ySm9JDqQN1ohJX
# OZOl0EkwWF4g9WqSSTQ6UYWk7GTmf7Rpu77OP3sBjQFtEgl2ouYAbHSSqU6l8bkO
# 6Vp6pcqkpJPzFBH2z58OAuDk6M/A8UvM4mB5GQmQBmNlbd57NCPCM/CUNHwrblD6
# bc5tuo6lMRBa9LEmR1GBkZryw59c3ORkp1E+vHNFAGPipnimd3xO8Foy/A91Mmaz
# 8J/7kHF/LGT6lMHi2fyNeRv/zDDEdnmzMMTtduNmY+WDm/HdT0jmnYZ8ZMmRcKMP
# V+h2ozMpmBSFIu81shCAFK93RDbWjDhLH1I/qZn8hxxiBF1GTVowptHo8MQqJv8M
# n+wG+Raa7BjMcrYKzcjFEnHGmiWyhcxRS8NU2FnNSEV9ULRCAoiKQzDsZHDnp68C
# VPLom8I/2vQIBSyDseSk1jmyry3WrlPgY+XOqB+nkde9VQjFU0ZOGzeY4yddFx6n
# aL/iKYZ+xIhD5OCL12ZZkU5Vdx0A2FcMxp6hghd3MIIXcwYKKwYBBAGCNwMDATGC
# F2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEPMA0GCWCGSAFlAwQCAQUAMHgG
# CyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEF
# AAQgKgW4FT0tj9sq4Hda273DEtGp5UEAj/Ly4C60TF8ueNACEQDSZFxCcIFc9Xzz
# in3nbwjsGA8yMDI2MDgyNTA3NDEzOFqgghM6MIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCBrQwggScoAMCAQICEA3HrFcF
# /yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8G
# A1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoX
# DTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNq
# EY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fk
# HUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EE
# bkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8
# NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUU
# FREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP
# 9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKW
# xdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespY
# MQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrP
# V6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+
# zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK
# 4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZx
# ML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97fr
# PBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+
# NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYA
# gwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA
# 1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+
# BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06
# VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284
# NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDez
# ooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM
# 9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpS
# M9LHJmyrxaFtoza2zNaQ9k+5t1wwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOII
# QBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0Rp
# Z2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTEx
# MDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/m
# kHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4
# FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMy
# lNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq8
# 68nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe
# 3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMq
# bpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxG
# j2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORF
# JYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhE
# lRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0vias
# tkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LW
# RV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNV
# HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNV
# HSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYI
# KwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAR
# BgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6Cj
# dBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/
# gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcud
# T6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3o
# sdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1
# VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eq
# XijiuZQxggN8MIIDeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3Rh
# bXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgw
# DQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwG
# CSqGSIb3DQEJBTEPFw0yNjA4MjUwNzQxMzhaMCsGCyqGSIb3DQEJEAIMMRwwGjAY
# MBYEFN1iMKyGCi0wa9o4sWh5UjAH+0F+MC8GCSqGSIb3DQEJBDEiBCBbTixZIkFg
# U7UcUdiFVlIilfcjcu9SalUxzYZg4LdqvjA3BgsqhkiG9w0BCRACLzEoMCYwJDAi
# BCBKoD+iLNdchMVck4+CjmdrnK7Ksz/jbSaaozTxRhEKMzANBgkqhkiG9w0BAQEF
# AASCAgAdKkQuFRdWZGH8CxQgbjkC4hgMT65T45va7we/xf4q04df9uAFKSRwiD2L
# aD/gLW/b/GeK5xeYiA4aYTXmbAxLX9RAsD7lOPF+jh0jJQm95YFtTN6isac7x2l0
# Iaj3Z4GbyBOJA/0FpVxJeib8k3oT9kzO3ikQ4G6kKXt193InSaSCAMTIwXHnyEfA
# JA1654asc1D9jPFkLppLeVkHaGSD9qxW2zb6jKg3+mlv++HLv3GET1+PmqrTrWV2
# fZWKTlKJ4f9mvZcqe1V6Ja01KSwEIJPa0Lv2To08zm8Jx18dcjpsDuATKdMbni4Z
# yo6DEQq9wvaXC8IXMTnyBK50aSwapK8VfRuXPpAcYLnbE0fcHcxafEhPUBflk1mL
# PrBx+ErL9JgbFYZy+JkPJTlz72Py6WPlS5H7xKkpqjOSnhAid/zslPP35U1Id2CR
# fuu3Kc6s82YkpvbE4r6xS2HVvRAijbjMpxr+sQ2lZc9jzYstk9Bv+bEcX4kx2DTE
# IVueQH/f/Kth2NjxmlW/P3FX1jDs2PyNvZJ9vxYpV1xrWhxRFFDk4vf2FyUa8fI7
# pOaGwIFLG2UC+tXPFbti9D+JKaepXNaM1HG1U96gw0eiYDh/i5T6qYJ6eNU1itBC
# SKFNhGvrg7xCMO1tFEaaupxsEKf6IvncGOvwsxSePEdidcxMZQ==
# SIG # End signature block
