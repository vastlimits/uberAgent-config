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

function Test-vlBlockedProgram {
   <#
    .SYNOPSIS
        Tests if a program is blocked by tools like AppLocker or Windows Defender Application Control.
    .DESCRIPTION
        Tests if a program is blocked by tools like AppLocker or Windows Defender Application Control.
        Make sure to use the full path to the program to avoid potential security risks.
    .OUTPUTS
        A [bool] indicating if the program is blocked or not
    .EXAMPLE
        Test-vlBlockedProgram
    #>

   Param(
      [string]$ProgramPath
   )

   $result = [PSCustomObject]@{
      FileExists = $false
      IsBlocked  = $null
   }

   # Check if the program exists at the specified path
   if (-not (Test-Path $ProgramPath)) {
      return $result
   }
   else {
      $result.FileExists = $true
   }

   $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo

   $processStartInfo.FileName = $ProgramPath
   $processStartInfo.RedirectStandardError = $true
   $processStartInfo.RedirectStandardOutput = $true
   $processStartInfo.UseShellExecute = $false
   $processStartInfo.CreateNoWindow = $true

   $process = New-Object System.Diagnostics.Process
   $process.StartInfo = $processStartInfo

   try {
      $process.Start() | Out-Null
      $process.WaitForExit()

      # the program is not blocked
      $result.IsBlocked = $false
      return $result
   }
   catch {
      # an exception occurred, indicating the program is blocked
      $result.IsBlocked = $true
      return $result
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
# MIIonAYJKoZIhvcNAQcCoIIojTCCKIkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD0VLXMNdrOIXXV
# NrwOpoYwtJM/d1Okhwngg1wZF0A2MKCCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxgho5MIIaNQIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggZQw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwKAYKKwYBBAGCNwIBDDEaMBigFoAUAEgAZQBsAHAAZQByAC4AcABz
# ADEwLwYJKoZIhvcNAQkEMSIEIA2eiowgoxGGMmiVVnctTQ1OfANppFO2+em/HN36
# Yd2dMA0GCSqGSIb3DQEBAQUABIIBgASXooy7kQCprn+c2C9CYeK9pL+oUQwT8JbN
# sIpxylRu5YM6l7gZ56YZm0AP4GMwer/LLcL5L5o0aTgb9ffTCfjEIMJMwWBvU7ny
# rLOj+m2g7S0MAlWT6txB+B+IcqVi1illBLRj9ZwW32KVYpJhmS1ySLl7cK6Yo7Sp
# lzEb6k6nEf6cq2QO6vY8iDp2CiUxz7yCwgQLUBvi0+z9RH+MxnUc3J8g401nSoZq
# LqTaLwqc+eQ4FE8ejz3ZsnrCPGmW8VABM1t6AlNHHfU2wRJ2MNtKTe8glhTmx+bV
# ahN4D3dyaSvN3iCZFKIQEFTbJk12UjkJyki28AQNVg3auHk9BC28T2g2IWBnZo4t
# ZCFiO/heb01vK4LxgIp8t7T/EslGXKBPZeRHYZqyCeqqdh1aOql9cpVabX20uj/T
# ulTPA5xOhDKAfFxlzLjJkRPnaEj/+9kSNc9x+YIVSpJM4+3QV2HBBc/9YJIQ9b6J
# +pD0ElHV7cM/Vj40dSHTGccbLMVQBKGCF3YwghdyBgorBgEEAYI3AwMBMYIXYjCC
# F14GCSqGSIb3DQEHAqCCF08wghdLAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZI
# hvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCh
# +5ydsL3Da8rYh379mzhmMg3QtyVAr/WMLKwDYRsw9AIQb2qKqXW5b0A/vpbrp3IG
# OxgPMjAyNjA4MjUwNzQwNTVaoIITOjCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBa
# Fw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0
# YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvR
# xUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtk
# epErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZ
# fKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANw
# qAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkI
# XIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8
# m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZ
# XOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq
# 4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7
# u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh
# 86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCC
# AZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgw
# HwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1l
# U3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKg
# UIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGlt
# ZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYG
# Z4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmu
# YEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ3
# 8U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP
# 1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAY
# H2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3
# i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ
# 6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBP
# C1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILf
# JdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn
# +OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71Mc
# VWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk
# ++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcwgga0MIIEnKADAgECAhANx6xXBf8hmS5A
# QyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAx
# MTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcy
# bEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzT
# qpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftB
# dsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3
# mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6z
# MUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS
# 5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBB
# BnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqL
# XvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7ps
# NOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeE
# WvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCC
# AVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv
# 1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/
# BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0
# LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvI
# tTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/m
# S83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgX
# f9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liy
# rukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+
# Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2
# ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipD
# oq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6Ax
# nJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAl
# Z66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1
# MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZs
# q8WhbaM2tszWkPZPubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjAN
# BgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2Vy
# dCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1
# OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN67
# 5F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaX
# bR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQ
# Lt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82s
# NEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4Da
# tpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwh
# TNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98Fp
# iHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppE
# GSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+
# 9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56
# rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8
# oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/
# BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgw
# FoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUF
# BwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMG
# CCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRB
# c3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0g
# BAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW
# 1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH3
# 8nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMT
# dydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY
# 9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyer
# bHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmU
# MYIDfDCCA3gCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHanlXRoMA0GCWCG
# SAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG
# 9w0BCQUxDxcNMjYwODI1MDc0MDU1WjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBTd
# YjCshgotMGvaOLFoeVIwB/tBfjAvBgkqhkiG9w0BCQQxIgQg7TyZTSHO+N+l0lNL
# /KmgtM17XlnQ1quB7hze1cAZ14cwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgSqA/
# oizXXITFXJOPgo5na5yuyrM/420mmqM08UYRCjMwDQYJKoZIhvcNAQEBBQAEggIA
# FaDsvaIrIP4JTC5URobsFUxQOb5wX/2129ccciXHsP5+vvECF5CT4zmDWTqzZzxL
# eo4G8nWy9YxpKs15Bdz2hnSi3PfSpFdbjxnLuyJErItVW2TdEaNABMdx6lUqkmxJ
# CfS27qorR2aJ0jD8z9y5S5OZnZl/umg8saWw0bhQH8dYuE/hp89EozBSqV2ohsZN
# 2pBOtR4LdMGGcvKjvB6SDt5LEbGmzhag4eP+QbSiFGpHD7lynt0sOxKLmmZzgpcA
# QC1xVrwAI5btVmtF4JK/vFVSNozw+MbyyFYMdIr3fIP2Bps5/VdVMmN2udvPErR5
# f0Jfx+oaExGyFowgqt704JP335EyRRNmMzJ4ExejaWzN9mMhgeQL4TVcOEjKPMN6
# HL0pJVgDK3aAPImyyO+zoO+6+sUw4//INWTIPdh2TDfoN4sPO1qKgQvIOZucbWE0
# mxy18Gma1ejmD44yPtEuPAmykXTbvRpdHU9H4+LtqbyWwL1bJ4xHkZv9mljT0q9g
# qZobSSibIanl8B9PbyYEys/aCbab/6JpTyyQ3evAM3JxXSZXMgum8pUmSguV9ayJ
# MBm64GHGDlXCvAvWjopHxBLFEWGbvrnGN/jAwEYQcA+aPbS3ZhFHwWsdHziomApB
# Ca7HgCPFs706d8R9mpNHEzGFeaGrEd0DqmZmX6Rx7ms=
# SIG # End signature block
