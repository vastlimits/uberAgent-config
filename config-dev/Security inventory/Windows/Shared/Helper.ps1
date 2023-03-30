#Requires -Version 3.0

#define global variable that contains a list of timers.
$global:debug_timers = @()

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
        return Get-vlOsArchitecture
    #>

   return (Get-CimInstance Win32_operatingsystem).OSArchitecture
}

function Get-vlIsWindows7 {
   <#
    .SYNOPSIS
        Check if the OS is Windows 7
    .DESCRIPTION
        Check if the OS is Windows 7
    .OUTPUTS
        A boolean indicating if the OS is Windows 7
    .EXAMPLE
        return Get-vlIsWindows7
    #>

   $osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version
   if ($osVersion -match "^6\.1") {
      return $true
   }
   else {
      return $false
   }
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
        Get the value of a registry key
    .DESCRIPTION
        Get the value of a registry key
    .PARAMETER Hive
        The hive of the registry key. Valid values are "HKLM", "HKU", "HKCU" and "HKCR"
    .PARAMETER Path
        The path to the registry key
    .PARAMETER Value
        The name of the value to read
    .OUTPUTS
        The value of the registry key or an empty string if the key was not found
    .EXAMPLE
        Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "ProductName"
    #>

   [CmdletBinding()]
   [OutputType([Object])]
   param (
      [Parameter(Mandatory = $true)]
      [ValidateSet("HKLM", "HKU", "HKCU", "HKCR")]
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
         elseif ($hive -eq "HKCR") {
            $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($Path);
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
         return $null
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
        return Get-vlRegSubkeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    #>

   [CmdletBinding()]
   [OutputType([Object])]
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

         return [Object]@()
      }
      finally {
      }
   }

   end {

   }
}

##### Debugging utilities #####

function Add-vlTimer {
   <#
    .SYNOPSIS
        Start a timer
    .DESCRIPTION
        Start a timer
    .PARAMETER Name
        The name of the timer
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Start-vlTimer -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name
   )
   begin {

   }

   process {
      $timer = New-Object -TypeName psobject -Property @{
         Name  = $Name
         Start = (Get-Date)
      }
      $global:debug_timers += $timer
   }

   end {

   }
}

function Restart-vlTimer {
   <#
    .SYNOPSIS
        Restart a timer
    .DESCRIPTION
        Restart a timer
    .PARAMETER Name
        The name of the timer
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Restart-vlTimer -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name
   )
   begin {

   }

   process {
      $timer = $global:debug_timers | Where-Object { $_.Name -eq $Name }
      if ($null -ne $timer) {
         $timer.Start = (Get-Date)
      }
   }

   end {

   }
}

function Get-vlTimerElapsedTime {
   <#
    .SYNOPSIS
        Get the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .DESCRIPTION
        Get the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .PARAMETER Name
        The name of the timer
    .PARAMETER Unit
        The unit of time to return. Valid values are "sec" and "ms"
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Get-vlTimerElapsedTime -Name "timer1"
    #>

   [CmdletBinding()]
   [OutputType([System.Int64])]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name,
      [ValidateSet("sec", "ms")]
      [string]$Unit = "ms"
   )
   begin {

   }

   process {
      $timer = $global:debug_timers | Where-Object { $_.Name -eq $Name }
      if ($null -ne $timer) {
         $elapsed = (Get-Date) - $timer.Start
         if ($Unit -eq "sec") {
            return $elapsed.TotalSeconds
         }
         else {
            return $elapsed.TotalMilliseconds
         }
      }
      else {
         return 0
      }
   }

   end {

   }
}

function Write-vlTimerElapsedTime {
   <#
    .SYNOPSIS
        Write the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .DESCRIPTION
        Write the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .PARAMETER Name
        The name of the timer
    .PARAMETER Unit
        The unit of time to return. Valid values are "sec" and "ms"
    .PARAMETER UseFile
        Write the elapsed time to a file
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Write-vlTimerElapsedTime -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name,
      [Parameter(Mandatory = $false)]
      [bool]$UseFile = $false,
      [Parameter(Mandatory = $false)]
      [ValidateSet("sec", "ms")]
      [string]$Unit = "ms"
   )
   begin {

   }

   process {
      $elapsed = Get-vlTimerElapsedTime -Name $Name -Unit $Unit
      if ($UseFile) {
         Add-Content -Path "script_debug.log" -Value "${Name}: $elapsed $Unit"
      }
      else {
         Write-Host "${Name}: $elapsed $Unit"
      }
   }

   end {

   }
}