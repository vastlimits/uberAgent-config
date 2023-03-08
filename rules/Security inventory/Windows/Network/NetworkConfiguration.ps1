
function Get-vlOsArchitecture {
    <#
    .SYNOPSIS
        Get the OS architecture
    .DESCRIPTION
        Get the OS architecture of the current machine as a string. Valid values are "32-bit" and "64-bit"
        This cmdlet is only available on the Windows platform.
        Get-CimInstance was added in PowerShell 3.0
    .LINK
        https://uberagent.com
    .OUTPUTS
        A string containing the OS architecture. Valid values are "32-bit" and "64-bit"
    .EXAMPLE
        return New-vlResultObject($result)
    #>

    return (Get-CimInstance Win32_operatingsystem).OSArchitecture
}

function New-vlErrorObject {
    <#
    .SYNOPSIS
        Generate an error object for the result of a function
    .DESCRIPTION
        Generate an error object for the result of a function that can be returned to the caller
    .PARAMETER Context
        The context of the error / exception    
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the error code and error message
    .EXAMPLE
        catch {
            return New-vlErrorObject($_)
        }
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $context,
        $score = 0
    )

    return [PSCustomObject]@{
        Result       = ""
        ErrorCode    = $context.Exception.MessageId
        ErrorMessage = $context.Exception.Message
        Score        = $score
    }
}

function New-vlResultObject {
    <#
    .SYNOPSIS
        Generate a result object for the result of a function
    .DESCRIPTION
        Generate a result object for the result of a function that can be returned to the caller
    .PARAMETER result
        The result that should be returned
    .NOTES
        The result will be converted to JSON
        ConvertTo-Json was added in PowerShell 3.0
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the result, error code and error message will be set to empty
    .EXAMPLE
        New-vlResultObject($result)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $result,
        $score,
        $riskScore
    )

    return [PSCustomObject]@{
        Result       = ConvertTo-Json $result -Compress
        ErrorCode    = 0
        ErrorMessage = ""
        Score        = $score
        RiskScore    = $riskScore
    }
}

function Get-vlRegValue {
    <#
    .SYNOPSIS
        Generate a result object for the result of a function
    .DESCRIPTION
        Generate a result object for the result of a function that can be returned to the caller
    .PARAMETER Hive
        The hive to read from. Valid values are "HKLM", "HKU" and "HKCU"
    .PARAMETER Path
        The path to the registry key
    .PARAMETER Value
        The name of the value to read
    .NOTES
        This function will return an empty string if the value does not exist.
        Microsoft.Win32.Registry is part of the .NET Framework since version 1.0.
        PowerShell added support NetFramework in version 2.0. So the min required version is of PowerShell is 2.0
    .LINK
        https://uberagent.com
    .OUTPUTS
        A string containing the value of the registry key or an empty string if the value does not exist
    .EXAMPLE
        Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "ProductName"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [string]$Value
    )
    begin {
        
    }
    
    process {

        try {
            $regKey = $null
            $regKeyValue = "";
            if ($Hive -eq "HKCU") {
                $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path);
                if ($null -ne $regKey) {
                    $regKeyValue = $regKey.GetValue($Value)
                }
                return $regKeyValue;
            }
            elseif ($hive -eq "HKU") {
                $regKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($Path);
                if ($null -ne $regKey) {
                    $regKeyValue = $regKey.GetValue($Value);
                }
                return $regKeyValue;
            }
            else {
                $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path);
                if ($null -ne $regKey) {
                    $regKeyValue = $regKey.GetValue($Value);
                }
                return $regKeyValue;
            }
        }
        catch {
            Write-Verbose "Registry $Hive\$Path was not found"
            return ""
        }
        finally {
            if ($null -ne $regKey) {
                Write-Verbose "Closing registry key $Hive\$Path"
                $regKey.Dispose()
            }
        }
    }

    end {
    }
}


function Get-vlRegSubkeys {
    <#
    .SYNOPSIS
        Generate a result object for the result of a function
    .DESCRIPTION
        Generate a result object for the result of a function that can be returned to the caller
    .PARAMETER Hive
        The hive to read from. Valid values are "HKLM", "HKU" and "HKCU"
    .PARAMETER Path
        The path to the registry key
    .NOTES
        The result will be converted to JSON.
        Microsoft.Win32.Registry is part of the .NET Framework since version 1.0.
        PowerShell added support NetFramework in version 2.0. So the min required version is of PowerShell is 2.0
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the result, error code and error message will be set to empty
    .EXAMPLE
        return New-vlResultObject($result)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    begin {

    }
    
    process {
        try {
            Write-Verbose "Get-RegSubkeys: $Hive\$Path"
            $regKey = $null

            if ($Hive -eq "HKLM") {
                $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path)
            }
            elseif ($Hive -eq "HKU") {
                $regKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($Path)
            }
            else {
                $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path)
            }

            if ($null -eq $regKey) {
                Write-Verbose "Registry $Hive\$Path was not found"
                return @()
            }
        
            $subKeys = $regKey.GetSubKeyNames()

            return $subKeys
        }
        catch {
            Write-Verbose "Error reading registry $Hive\$Path"
            Write-Verbose $_.Exception.Message

            return @()
        }
        finally {
            if ($null -ne $regKey) {
                $regKey.Dispose()
            }
        }
    }
    
    end {
    
    }
}


function Get-vlRegSubkeys2 {
    <#
    .SYNOPSIS
        Read all the subkeys from a registry path
    .DESCRIPTION
        Read all the subkeys from a registry path
    .PARAMETER Hive
        The hive to read from. Valid values are "HKLM", "HKU" and "HKCU"
    .PARAMETER Path
        The path to the registry key        
    .LINK
        https://uberagent.com
    .OUTPUTS
        
    .EXAMPLE
        return Get-vlRegSubkeys2 -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    begin {

    }
    
    process {
        try {
            $registryItems = @()

            $path = $Hive + ":\" + $Path
            if (Test-Path -Path $path) {
                $keys = Get-ChildItem -Path $path
                $registryItems = $keys | Foreach-Object { Get-ItemProperty $_.PsPath }
            }
            return $registryItems
        }
        catch {
            Write-Verbose "Error reading registry $Hive\$Path"
            Write-Verbose $_.Exception.Message

            return @()
        }
        finally {
        }
    }
    
    end {
    
    }
}


function Get-vlRegKeyValues {
    <#
    .SYNOPSIS
        Read all the keys from a registry path
    .DESCRIPTION
        Read all the keys from a registry path
    .PARAMETER Hive
        The hive to read from. Valid values are "HKLM", "HKU" and "HKCU"
    .PARAMETER Path
        The path to the registry key        
    .LINK
        https://uberagent.com
    .OUTPUTS
        
    .EXAMPLE
        return Get-vlRegKeyValues -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("HKLM", "HKU", "HKCU")]
        [string]$Hive,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    begin {

    }
    
    process {
        try {
            $registryItems = @()
            Write-Verbose "Get-RegSubkeys: $Hive\$Path"
            $regKey = $null
    
            if ($Hive -eq "HKLM") {
                $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path)
            }
            elseif ($Hive -eq "HKU") {
                $regKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($Path)
            }
            else {
                $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path)
            }
    
            if ($null -eq $regKey) {
                Write-Verbose "Registry $Hive\$Path was not found"
                return @()
            }
            
            $valueNames = $regKey.GetValueNames()
    
            #check if $valueNames is empty
            if ($null -eq $valueNames -or $valueNames.Count -eq 0) {
                return @()
            }

            #loop through $valueNames and get the value
            foreach ($valueName in $valueNames) {
                $value = $regKey.GetValue($valueName)
                $registryItems += New-Object -TypeName psobject -Property @{
                    Name  = $valueName
                    Value = $value
                }
            }
            return $registryItems
        }
        catch {
            Write-Verbose "Error reading registry $Hive\$Path"
            Write-Verbose $_.Exception.Message

            return @()
        }
        finally {
            if ($null -ne $regKey) {
                $regKey.Dispose()
            }
        }
    }
    
    end {
    
    }
}

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
      
      if (Test-Path HKLM:\SYSTEM\CurrentControlSet\services\mrxsmb10)
      {
         $mrxsmb10 = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\services\mrxsmb10" -Value "Start"
         $LanmanWorkstation = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Value "DependOnService"

         if ($mrxsmb10 -ne 4 -and $LanmanWorkstation -icontains "mrxsmb10") {
            $SMBv1 = $true
         }
      }

      if ($SMBv1 -eq $false) {
         $result = [PSCustomObject]@{
            enabled = $false
         }
         # SMBv1 is disabled
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            enabled = $true
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

      if ($SMBv1.Result -like '*true*')
      {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"
         $SMBSigningEnabled = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "EnableSecuritySignature"

         if ($SMBSigningRequired -eq 1) 
         {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10
         }
         elseif ($SMBSigningRequired -eq 0 -and $SMBSigningEnabled -eq 1) 
         {
            $result = [PSCustomObject]@{
               state = "Enabled"
            }
            # SMB signing is enabled but not required
            return New-vlResultObject -result $result -score 2
         }
         else 
         {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2
         }
      }
      elseif ($SMBv1.Result -like '*false*')
      {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"

         if ($SMBSigningRequired -eq 1) 
         {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10
         }
         else 
         {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2
         }
         
      }
      else 
      {
         Throw "Return of Get-vlNetworkConfigurationSMBv1 is invalid"
         return New-vlErrorObject($Error)
      }
   }
   catch 
   {
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
      if ((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object -Property 'TcpipNetbiosOptions' -eq 1).Count -eq 0)
      {
         $result = [PSCustomObject]@{
            enabled = $false
         }
         # NetBIOS is disabled
         return New-vlResultObject -result $result -score 10
      }
      else 
      {
         $result = [PSCustomObject]@{
            enabled = $true
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
      if (((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter IPEnabled=TRUE | Where-Object -Property 'WINSPrimaryServer' -ne $null).ServiceName).Count -eq 0)
      {
         $result = [PSCustomObject]@{
            enabled = $false
         }
         # WINS is not in usage
         return New-vlResultObject -result $result -score 10
      }
      else 
      {
         $result = [PSCustomObject]@{
            enabled = $true
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
      foreach ($Protocol in $Protocols) 
      {
         $null = $Enabled
         $null = $DisabledByDefault
         
         if (test-path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client")
         {
            $Enabled = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Value "Enabled"
            $DisabledByDefault = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Client" -Value "DisabledByDefault"

            if ($Enabled -eq 1 -OR $DisabledByDefault -eq 0)
            {
               $ProtocolsInUse += $Protocol
            }
         }
         else 
         {
            $ProtocolsInUse += $Protocol
         }
      }

      
      
      if ($ProtocolsInUse.Count -eq 0)
      {
         $result = [PSCustomObject]@{
            enabled = $false
         }
         # Outdated protocols are disabled
         return New-vlResultObject -result $result -score 10
      }
      else 
      {
         $result = [PSCustomObject]@{
            enabled = $ProtocolsInUse
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

   if ($params.Contains("all") -or $params.Contains("SMBv1")) {
       $SMBv1 = Get-vlNetworkConfigurationSMBv1    
       $Output += [PSCustomObject]@{
           Name         = "NetworkConfiguration - SMBv1"
           Score        = $SMBv1.Score
           ResultData   = $SMBv1.Result
           RiskScore    = 100
           ErrorCode    = $SMBv1.ErrorCode
           ErrorMessage = $SMBv1.ErrorMessage
       }
   }

   if ($params.Contains("all") -or $params.Contains("SMBSigning")) {
      $SMBSigning = Get-vlNetworkConfigurationSMBSigning    
      $Output += [PSCustomObject]@{
          Name         = "NetworkConfiguration - SMB Signing"
          Score        = $SMBSigning.Score
          ResultData   = $SMBSigning.Result
          RiskScore    = 40
          ErrorCode    = $SMBSigning.ErrorCode
          ErrorMessage = $SMBSigning.ErrorMessage
      }
  }

  if ($params.Contains("all") -or $params.Contains("NetBIOS")) {
   $NetBIOS = Get-vlNetworkConfigurationNetBIOS    
   $Output += [PSCustomObject]@{
       Name         = "NetworkConfiguration - NetBIOS"
       Score        = $NetBIOS.Score
       ResultData   = $NetBIOS.Result
       RiskScore    = 20
       ErrorCode    = $NetBIOS.ErrorCode
       ErrorMessage = $NetBIOS.ErrorMessage
   }
   }

   if ($params.Contains("all") -or $params.Contains("WINS")) {
      $WINS = Get-vlNetworkConfigurationWINS    
      $Output += [PSCustomObject]@{
          Name         = "NetworkConfiguration - WINS"
          Score        = $WINS.Score
          ResultData   = $WINS.Result
          RiskScore    = 20
          ErrorCode    = $WINS.ErrorCode
          ErrorMessage = $WINS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("SSLTLS")) {
      $SSLTLS = Get-vlNetworkConfigurationSSLTLS    
      $Output += [PSCustomObject]@{
          Name         = "NetworkConfiguration - SSL/TLS"
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