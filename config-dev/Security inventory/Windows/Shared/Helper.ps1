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

function Get-vlOsVersion {
   <#
    .SYNOPSIS
        Retruns the OS version
    .DESCRIPTION
        Retruns the OS version
    .OUTPUTS
        A string containing the OS version
    .EXAMPLE
        return Get-vlOsVersion
   #>

   $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version

   return $osVersion
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
   # use CIM instead of WMI

   $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version

   if ($osVersion -match "^6\.1") {
      return $true
   }
   else {
      return $false
   }
}

function  Get-vlIsWindowsServer {
   <#
    .SYNOPSIS
        Check if the OS is a Windows Server
    .DESCRIPTION
        Check if the OS is a Windows Server
    .OUTPUTS
        A boolean indicating if the OS is a Windows Server
    .EXAMPLE
        return Get-vlIsWindowsServer
    #>

   try {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem
      if ($os.Caption -like "*Server*") {
         return $true
      }
      else {
         return $false
      }
   }
   catch {
      Write-Output $_.Exception.Message
      return $null
   }
}

function Convert-vlEnumToString ($object) {
   <#
    .SYNOPSIS
        Checks if the input object is an enum and converts it to a string
    .DESCRIPTION
        Checks if the input object is an enum and converts it to a string
    .OUTPUTS
         an object with all enums converted to strings
    .EXAMPLE
        Convert-vlEnumToString
    #>

   $outputObj = $object | ForEach-Object {
      if ($_ -is [Enum]) {
         $_.ToString()
      }
      elseif ($_ -is [Array]) {
         $_ | ForEach-Object { Convert-vlEnumToString $_ }
      }
      elseif ($_ -is [PSCustomObject] -and $_.GetType().Name -eq 'PSCustomObject') {
         $properties = $_ | Get-Member -MemberType Properties
         $newObj = New-Object -TypeName PSCustomObject
         foreach ($prop in $properties) {
            $propValue = $_.($prop.Name)
            $newObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value (Convert-vlEnumToString $propValue)
         }
         return $newObj
      }
      else {
         return $_
      }
   }
   return $outputObj
}

function New-vlErrorObject {
   <#
    .SYNOPSIS
        Generate an error object for the result of a function
    .DESCRIPTION
        Generate an error object for the result of a function that can be returned to the caller
    .PARAMETER Context
        The context of the error/exception
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
      $message = $null,
      $errorCode = $null
   )

   $finalCode = if ($context.Exception.HResult) { $context.Exception.HResult } else { 1 }

   if ( $null -ne $errorCode) {
      $finalCode = $errorCode
   }

   return [PSCustomObject]@{
      Result       = $null
      ErrorCode    = $finalCode
      ErrorMessage = if ( $null -ne $message) { $message } else { $context.Exception.Message }
      Score        = $null
      RiskScore    = $null
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
      Result       = ConvertTo-Json $result -Compress -Depth 3
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
    .PARAMETER IncludePolicies
        Checks also the GPO policies path
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
      [string]$Value,
      [Parameter(Mandatory = $false)]
      [bool]$IncludePolicies = $false
   )

   process {
      try {
         #check if $Path starts with \ then remove it
         if ($Path.StartsWith("\")) {
            $Path = $Path.Substring(1)
         }

         $regKey = $null
         $regKeyValue = $null;
         if ($Hive -eq "HKCU") {
            # Get the registry key for the current user
            $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path);
         }
         elseif ($hive -eq "HKU") {
            # Get the registry key for all users
            $regKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($Path);
         }
         elseif ($hive -eq "HKCR") {
            # Get the registry key for the classes root
            $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($Path);
         }
         else {
            # Get the registry key for the local machine
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path);
         }

         if ($IncludePolicies -eq $true) {
            # check if $path contains "SOFTWARE" if true then replace with "SOFTWARE\Policies\"
            $gpo_store32_path = $Path -replace "^SOFTWARE\\", "SOFTWARE\Policies\"
            $gpo_store32 = Get-vlRegValue -Hive $Hive -Path $gpo_store32_path -Value $Value

            $gpo_store64_path = $Path -replace "^SOFTWARE\\", "SOFTWARE\WOW6432Node\Policies\"
            $gpo_store64 = Get-vlRegValue -Hive $Hive -Path $gpo_store64_path -Value $Value

         }

         if ($null -ne $regKey) {
            $regKeyValue = $regKey.GetValue($Value);
         }

         if ($gpo_store32) {
            $regKeyValue = $gpo_store32
         }
         elseif ($gpo_store64) {
            $regKeyValue = $gpo_store64
         }

         return $regKeyValue;
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

         #check if $Path starts with \ then remove it
         if ($Path.StartsWith("\")) {
            $Path = $Path.Substring(1)
         }

         $path = $Hive + ":\" + $Path
         if (Test-Path -Path $path) {
            $keys = Get-ChildItem -Path $path
            $registryItems = $keys | Foreach-Object {
               try {
                  #if Property length is > 0 then Get-ItemProperty else add the key to the array
                  if ($null -ne $_.Property) {
                     Get-ItemProperty $_.PsPath
                  }
                  else {
                     $_
                  }
               }
               catch {
                  $_
               }
            }
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

function Get-vlRegistryKeyValues {
   <#
    .SYNOPSIS
        Retrieves all ValueNames and their associated Values from a specified registry key.
    .DESCRIPTION
        This function fetches all ValueNames and their corresponding Values from a provided registry path. It allows querying different hives like HKLM, HKU, and HKCU.
    .PARAMETER Hive
        The registry hive to query from. Acceptable values are "HKLM", "HKU", and "HKCU".
    .PARAMETER Path
        Specifies the path to the desired registry key.
    .OUTPUTS
        System.Object. Outputs a custom object for each Value in the specified registry key which contains the ValueName and its associated Value.
    .EXAMPLE
        Get-vlRegistryKeyValues -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        This example queries the "SOFTWARE\Microsoft\Windows NT\CurrentVersion" key in the HKLM hive and returns all its ValueNames and Values.
#>

   param (
      [Parameter(Mandatory = $true)]
      [ValidateSet('HKLM', 'HKU', 'HKCU')]
      [string]$Hive,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )

   try {
      if ($Path.StartsWith("\")) {
         $Path = $Path.Substring(1)
      }

      $RegistryPath = $Hive + ":\" + $Path

      # Check if the Registry Key exists
      if (-not (Test-Path $RegistryPath)) {
         return [Object]@()
      }

      # Get ValueNames and Values from the Registry Key
      $key = Get-Item -Path $RegistryPath
      $outputObject = @{}
      $key.GetValueNames() | ForEach-Object {
         $outputObject[$_] = $key.GetValue($_)
      }

      return [PSCustomObject]$outputObject
   }
   catch {
      return [Object]@()
   }
}

function Get-vlHashTableKey {
   <#
    .SYNOPSIS
        Retrieves the key from a hashtable corresponding to a specified value.
    .DESCRIPTION
        This function takes as input a hashtable and a value. It searches the hashtable for entries where the value matches the provided value.
        It returns the key(s) of matching entries.
    .PARAMETERS
        - hashTable: The hashtable to search.
        - value: The value to search for in the hashtable.
    .OUTPUTS
        Returns the key(s) from the hashtable where the value matches the input value. If no match is found, returns $null. If multiple matches are found, returns all matching keys.
    .EXAMPLE
        $parsedProfile = Get-vlHashTableKey -hashTable $FW_PROFILES -value $rule.Profiles
    #>

   param(
      [Hashtable]$hashTable,
      [Object]$value
   )

   $hashTable.GetEnumerator() | Where-Object { $_.Value -eq $value } | ForEach-Object { $_.Name }
}


function Get-vlHashTableKeys {
   <#
    .SYNOPSIS
        Returns the key names from a hashtable that correspond to the bits set in a given flag value.
    .DESCRIPTION
        This function takes a hashtable and a flag value as input. It uses bitwise operations to check which bits are set in the flag value.
        For each set bit, it finds the corresponding key in the hashtable and returns these keys.
    .PARAMETERS
        - hashTable: A hashtable where each value is a power of 2, corresponding to a bit position in a flag.
        - value: The flag value to check. This should be an integer where each set bit corresponds to a key in the hashtable.
    .OUTPUTS
        Returns a list of key names from the hashtable that correspond to the bits set in the flag value.
    .EXAMPLE
        $parsedProfile = Get-vlHashTableKeys -hashTable $FW_PROFILES -value $rule.Profiles
    #>

   param(
      [Hashtable]$hashTable,
      [Object]$value
   )

   $hashTable.GetEnumerator() | Where-Object { ($value -band $_.Value) -ne 0 } | ForEach-Object { $_.Name }
}


function Get-vlTimeScore($time) {
   <#
    .SYNOPSIS
        Function that calculates the last sync score based on the time.
    .DESCRIPTION
        Function that calculates the last sync score based on the time.
    .OUTPUTS
        Returns the score based on the time.
    .EXAMPLE
        Get-vlTimeScore
    #>

   if ($null -eq $time) {
      return -3
   }

   #check if time has type DateTime if not then convert it
   if ($time.GetType().Name -ne "DateTime") {
      $time = [DateTime]$time
   }

   #check if time is less than 14 days
   if ($time -lt (Get-Date).AddDays(-14)) {
      return -3
   }

   #check if time is less than 7 days
   if ($time -lt (Get-Date).AddDays(-7)) {
      return -2
   }

   #check if time is less than 2 days
   if ($time -lt (Get-Date).AddDays(-2)) {
      return -1
   }

   return 0
}

function Get-vlTimeString {
   <#
   .SYNOPSIS
      Converts a timestamp to a formatted string representing the date and time.

   .DESCRIPTION
      The Get-vlTimeString function takes a timestamp as input and returns a formatted string representation of the date and time. It uses the "yyyy-MM-ddTHH:mm:ss" format.

   .PARAMETER timeStamp
      Specifies the timestamp to convert to a string representation. This parameter is mandatory.

   .OUTPUTS
      The function outputs a string representing the formatted date and time.

   .EXAMPLE
      Get-vlTimeString time (Get-Date)
      Returns the current date and time in the "yyyy-MM-ddTHH:mm:ss" format.

   .EXAMPLE
      Get-vlTimeString time $null
      Returns an empty string.
   #>

   [CmdletBinding()]
   [OutputType([string])]
   param (
      $time
   )

   try {
      if ($null -ne $time) {
         return $time.ToString("yyyy-MM-ddTHH:mm:ss")
      }
      else {
         return ""
      }
   }
   catch {
      return ""
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
      # check if $Name is not null or empty
      if ([string]::IsNullOrEmpty($Name)) {
         return
      }

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
      # check if $Name is not null or empty
      if ([string]::IsNullOrEmpty($Name)) {
         return
      }

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
         return [System.Int64]0
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
         Write-Debug "${Name}: $elapsed $Unit"
      }
   }

   end {

   }
}