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

         $firewall = Get-NetFirewallProfile -All -ErrorAction Stop
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
            $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
            $appFilter = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop

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

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


Write-Output (Get-vlFirewallCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCkjG6cXweq5pEU
# JKvJV/yAR1wA1hJO4cHBcya0351n1KCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg885Tt7MGOacR
# GR4xMQzqpqjgBrA+z4XaXpyimLiJMAQwDQYJKoZIhvcNAQEBBQAEggIAXtd9D/y9
# qilFpgVu09OFjcZiaaFsBgPx4H+1eK9Tk4TsINEGAxD7+H7JmTIJC4NrAV8HCtky
# fZKuQXvrFg3VWTuhpCTfTh2LQbVPQwmq0veflppPYyvQYAGkVp2Y3Du+sx29Dd/8
# ErRSmDUOifJS/0wdkeeStT+ysHAT3bm+zKlMBmmmFoDm1yt5375bd1mrLqZ0l5Qm
# H/gzH8Zgq2gK8Zzr76UB4f0Oiao5IXQ4dIxN4fNH1XD6DeshXY8+xW1sBNYmyqQ3
# zuAX1jK61CgUnhDWWtTfTO2y0tRL7jL7yEZYOLsnxRABvDcyBcw/ox7viaRoUf0L
# NxvZPs451eNb5YtOmm8wNBPOQVUx1QwwYHF/3jIXzO3ByRNt64wwPx3hK8gAxsCY
# EvYwE6AMIZVeaEbO/nPucfEvQ1xCsqax7mr9E2xFq3l+IuO7q/kzl11G80+OrFmg
# Cwmk8GTz2gIwaY/9//fqkTQrKyRhVQq+WrgJMxnTRIZML5tn9pfi65PFPBr93kXK
# QJyRR3Bq59St+ClWdHjr7MEijKUCD3FTviI1hLyEL41KGTDWztnHsJPGbHFcY0Eb
# LpOzbPP1lFRKYGPTdfHAucofEUQTXqNIGjD+yXnny3SX0xBlSCFQAnEZfQJ7bkz4
# Yb2LgYJppANeeQrqzVtjoAf/AGlUVV3CvVw=
# SIG # End signature block
