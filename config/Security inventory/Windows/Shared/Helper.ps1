#Requires -Version 3.0

#define global variable that contains a list of timers.
$global:debug_timers = @()

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
      if ($null -eq $_) {
         return ""
      }

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
            return New-vlErrorObject -context $_
        }
    #>

   [CmdletBinding()]
   param (
      $context,
      $message = $null,
      $errorCode = $null
   )

   if ( $null -ne $context) {
      $finalCode = if ($context.Exception.HResult) { $context.Exception.HResult } else { 1 }
   }
   else {
      $finalCode = 1
   }

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
      $result,
      $score,
      $riskScore
   )

   # check if top level attribues values of $result are empty or null and remove them
   if ($null -ne $result -and $result -is [psobject]) {
      $attributesToRemove = @()

      $result | Get-Member -MemberType NoteProperty | ForEach-Object {
         $value = $result.($_.Name)

         if ($null -eq $value -or
           ($value -is [string] -and [string]::IsNullOrEmpty($value)) -or
           ($value -is [array] -and $value.Count -eq 0) -or
           ($value -is [System.Collections.Generic.List[object]] -and $value.Count -eq 0)) {

            # The value is empty (null, empty string, empty array/list), exclude this property
            $attributesToRemove += $_.Name
         }
      }

      # check if $attributesToRemove contains any attributes and remove them
      if ($attributesToRemove.Count -gt 0) {
         foreach ($attribute in $attributesToRemove) {
            # remove the attribute from the result object
            $result.PSObject.Properties.Remove($attribute)
         }
      }
   }

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
        The value of the registry key or $null if the key was not found
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
        Retrieves all value names and their associated values from a specified registry key.
    .DESCRIPTION
        This function fetches all value names and their corresponding values from a provided registry path. It allows querying different hives like HKLM, HKU, and HKCU.
    .PARAMETER Hive
        The registry hive to query from. Acceptable values are "HKLM", "HKU", and "HKCU".
    .PARAMETER Path
        Specifies the path to the desired registry key.
    .OUTPUTS
        System.Object. Outputs a custom object for each Value in the specified registry key which contains the ValueName and its associated Value.
    .EXAMPLE
        Get-vlRegistryKeyValues -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        This example queries the "SOFTWARE\Microsoft\Windows NT\CurrentVersion" key in the HKLM hive and returns all its value names and values.
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

      # Get value names and values from the Registry Key
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

   if ($null -ne $hashTable) {
      $hashTable.GetEnumerator() | Where-Object { $_.Value -eq $value } | ForEach-Object { $_.Name }
   }
   else {
      return $null
   }
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

   if ($null -ne $hashTable) {
      $hashTable.GetEnumerator() | Where-Object { ($value -band $_.Value) -ne 0 } | ForEach-Object { $_.Name }
   }
   else {
      return $null
   }
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

function Get-vlIsCmdletAvailable {
   [CmdletBinding()]
   [OutputType([bool])]
   param (
      [Parameter(Mandatory = $true)]
      [string]$CmdletName
   )

   try {
      $cmdlet = Get-Command $CmdletName -ErrorAction Stop
      if ($null -ne $cmdlet) {
         return $true
      }
      else {
         return $false
      }
   }
   catch {
      return $false
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
        Add-vlTimer -Name "timer1"
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

function Write-vlDebugLog {
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
      [string]$Data,
      [Parameter(Mandatory = $false)]
      [bool]$UseFile = $false
   )

   process {
      # get current time and format it for the log with milliseconds like 2019-01-01 12:00:00.000
      $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

      if ($UseFile) {
         # use C:\Windows\Temp as default log path
         $logPath = "C:\\Windows\\Temp\\ua_script_debug.log"

         Add-Content -Path $logPath -Value "[$time] - ${data}"
      }
      else {
         Write-Debug "${Name}: $elapsed $Unit"
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

   process {
      $elapsed = Get-vlTimerElapsedTime -Name $Name -Unit $Unit
      Write-vlDebugLog -Data "${Name}: $elapsed $Unit" -UseFile $UseFile
   }

}
# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBa9Qn3HAcj/I+M
# fGoui2QiVC3HrXDgA0tthcD+RG4nCaCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgABKd9NJqYQPf
# VON61hADj4Mecw5xSQk0e3xsdwhDT90wDQYJKoZIhvcNAQEBBQAEggIAWZKhTPZQ
# qq9qoTxMGEE8LpzD5ApJFIx05blXNFti0u7OW1xFxl/3aXOgU0l1nuy5urb3uT4w
# gJfNzDgrWVOIcAPmyxNQdypdCqt/mlK0qNMCyjSPEfaAdsDZAqHnCqNFRKDku+ej
# q6UZV+DWlGQiTDXnpjD9N5YwB0MEMbDKACJwdhfyXmQjfwm3HXVZZGJ6PzVZEvvq
# 1YCRmF16dlEdlwk2+M0v+BipX+utz41gBZcIbV6Tu4MSb+RpzcmBbAKz5aHycJ9G
# z5gj4jVLZNqHC7xiMEI7m0G38HH7PJUREeamp8/M5cZcRtr+Ry53WGIrXmi6NM0m
# bFkvDhx74Orw2luuSkVKJPYfVFvD/unGZIFEroIwTMflHVRqzjPDWFKrXycquJoq
# ZqU5ixaV3jLSveP8erZ7hXFGple/WVa312RfJzD14S9Zcq3CgF8gzO5xbDPyDS8d
# aMkHqeeNjf2fFNrDaUylvZ3L0Fwculk/Q3dav8RYE+aX9GZm83Mgqlfwul08k1HA
# bL0CPML8/NujKZ3sfzZC9seXiBej3L0mhNYXQNbzMVGDcXv0tSiE6mVsk6WtAGnw
# vUJ1BF9ky4g63e3GArr+rkL37ub8FH0zJxFmdRyyM+OoYpkbkOhIQyfM8fCzYQQu
# d4OT0x5BGAObc4R5n0eP7cnHyYqd3blIcNA=
# SIG # End signature block
