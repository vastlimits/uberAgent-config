

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
    } else {
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


function Get-vlDefaultProgramForExtension {
    <#
    .SYNOPSIS
        Gets the default program for a specific file extension
    .DESCRIPTION
        Gets the default program for a specific file extension
    .OUTPUTS
        A [string] containing the path to the default program
    .EXAMPLE
        Get-vlDefaultProgramForExtension
    #>

    param (
        [Parameter(Mandatory = $true)]
        [string]$Extension
    )

    $progId = Get-vlRegValue -Hive "HKCR" -Path "\$Extension"
    if ($progId -ne $null) {
        $command1 = (Get-vlRegValue -Hive "HKCR" -Path "\$progId\shell\open\command")
        $command2 = (Get-vlRegValue -Hive "HKCR" -Path "\$progId\shell\printto\command")

        # select the one that is not null
        $command = if ($command1 -ne $null -and $command1 -ne "") { $command1 } else { $command2 }
        
        if ($command -ne $null) {
            return $command
        }
        else {
            Write-Debug "No 'open' command found for program ID $progId."
        }
    }
    else {
        Write-Debug "No default program found for extension $Extension."
    }
}

function Test-vlBlockedProgram {
    <#
    .SYNOPSIS
        Tests if a program is blocked by the system.
    .DESCRIPTION
        Tests if a program is blocked by the system.
    .OUTPUTS
        A [bool] indicating if the program is blocked or not
    .EXAMPLE
        Test-vlBlockedProgram
    #>

    Param(
        [string]$ProgramPath
    )

    $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processStartInfo.FileName = $ProgramPath
    $processStartInfo.RedirectStandardError = $true
    $processStartInfo.RedirectStandardOutput = $true
    $processStartInfo.UseShellExecute = $false
    $processStartInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processStartInfo

    $process.Start() | Out-Null
    $process.WaitForExit()

    $exitCode = $process.ExitCode

    if ($exitCode -ne 0) {
        # the program is blocked
        return $true
    }
    else {
        # the program is not blocked
        return $false
    }
}

function Get-CheckHTAEnabled {
    <#
    .SYNOPSIS
        Checks if HTA is enabled on the system.
    .DESCRIPTION
        Checks if HTA is enabled on the system.
    .LINK
        https://uberagent.com
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-CheckHTAEnabled
    #>

    try {
        $startProc = ""

        #$htaExecuteStatus = Run-vlHtaCode $htacode
        $htaRunBlocked = Test-vlBlockedProgram -ProgramPath "mshta.exe"

        $defaultLink = $true
        $startCmd = (Get-vlDefaultProgramForExtension -Extension ".hta").ToLower()

        if ($null -ne $startCmd -and $startCmd -ne "") {
            $startProc = (Split-Path $startCmd -Leaf)

            # check if $startProc contains space and if so, get the first part
            if ($startProc.Contains(" ")) {
                $startProc = $startProc.Split(" ")[0]
            }
        }
        else {
            $startProc = $null
        }

        # check if $status starts with "${env:SystemRoot}" and contains "mshta.exe"
        $winDir = ("${env:SystemRoot}").ToLower()

        if ($startCmd.StartsWith($winDir) -and $startCmd.Contains("mshta.exe")) {
            $defaultLink = $true
        }
        else {
            $defaultLink = $false
        }

        $result = [PSCustomObject]@{
            RunBlocked  = $htaRunBlocked
            OpenWith    = $startProc
            DefaultLink = $defaultLink
        }

        return New-vlResultObject -result $result -score 10
    }
    catch {
        return New-vlErrorObject -error $_
    }
}

function Get-BitlockerEnabled {
    <#
    .SYNOPSIS
        Checks if Bitlocker is enabled and used on the system.
    .DESCRIPTION
        Checks if Bitlocker is enabled and used on the system.
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-CheckHTAEnabled
    #>

    try {
        #check if bitlocker is enabled using Get-BitLockerVolume
        $bitlockerEnabled = Get-BitLockerVolume | Select-Object -Property MountPoint, ProtectionStatus, EncryptionMethod, EncryptionPercentage

        return New-vlResultObject -result $bitlockerEnabled 
    }
    catch {
        return New-vlErrorObject -error $_
    }
}

function Get-COMHijacking {
    <#
    .SYNOPSIS
        Checks if mmc.exe is hijacked
    .DESCRIPTION
        Checks if mmc.exe is hijacked
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-COMHijacking
    #>
    try {
        
        $expectedValue = "$($env:SystemRoot)\system32\mmc.exe ""%1"" %*"

        $value = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Classes\mscfile\shell\open\command"

        if (($value.ToLower()) -eq ($expectedValue.ToLower())) {
            $result = [PSCustomObject]@{
                Detected = $false
            }

            return New-vlResultObject -result $result -score 10
        }
        else {
            $result = [PSCustomObject]@{
                Detected = $true
            }
            return New-vlResultObject -result $result -score 0
        }
    }
    catch {
        return New-vlErrorObject -error $_
    }
}

function Get-vlTimeProviderHijacking {
    <#
    .SYNOPSIS
        Checks if w32time.dll is hijacked
    .DESCRIPTION
        Checks if w32time.dll is hijacked
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-vlTimeProviderHijacking
    #>

    try {
        $expectedValue = "$($env:SystemRoot)\system32\w32time.dll"

        $value = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Value "DllName"

        if (($value.ToLower()) -eq ($expectedValue.ToLower())) {
            $result = [PSCustomObject]@{
                Detected = $false
            }

            return New-vlResultObject -result $result -score 10
        }
        else {
            $result = [PSCustomObject]@{
                Detected = $true
            }
            return New-vlResultObject -result $result -score 0
        }
    }
    catch {
        return New-vlErrorObject -error $_
    }
}

function Get-vlWindowsPersistanceCheck {
    <#
    .SYNOPSIS
        Runs sfc /verifyonly and checks if CBS.log contains "corrupt" or "repaired"
    .DESCRIPTION
        Runs sfc /verifyonly and checks if CBS.log contains "corrupt" or "repaired"
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-vlWindowsPersistanceCheck
    #>
    
    try {
        $log_file = "$($env:SystemRoot)\Logs\CBS\CBS.log"

        #check if CBS Log exists and if so, delete it use %windir%\Logs\CBS\CBS.log
        if (Test-Path -Path $log_file) {
            Remove-Item -Path $log_file -Force
        }

        #run sfc /verifyonly and wait for it to finish run it hidden
        $sfc = Start-Process -FilePath "sfc.exe" -ArgumentList "/verifyonly" -Wait -WindowStyle Hidden
        
        #read the log file and check if it contains "corrupt" or "repaired"
        $defect = Get-Content $log_file | Select-String -Pattern "(corrupt|repaired)"
        $ix = 0
    }
    catch {
        $defect = $null
    }
}



function Get-WindowsConfigurationCheck {
    #set $params to $global:args or if empty default "all"
    $params = if ($global:args) { $global:args } else { "all" }
    $Output = @()


    if ($params.Contains("all") -or $params.Contains("WCHta")) {
        $checkHtaEnabled = Get-CheckHTAEnabled
        $Output += [PSCustomObject]@{
            Name         = "WCHta"
            DisplayName  = "WindowsConfiguration HTA"
            Description  = "Checks if HTA execution is enabled on the system."
            Score        = 0
            ResultData   = $checkHtaEnabled.Result
            RiskScore    = 100
            ErrorCode    = $COMHijacking.ErrorCode
            ErrorMessage = $COMHijacking.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("WCBitlocker")) {
        $checkBitlockerEnabled = Get-BitlockerEnabled
        $Output += [PSCustomObject]@{
            Name         = "WCBitlocker"
            DisplayName  = "WindowsConfiguration Bitlocker"
            Description  = "Checks if Bitlocker is enabled on the system."
            Score        = 0
            ResultData   = $checkBitlockerEnabled.Result
            RiskScore    = 100
            ErrorCode    = $COMHijacking.ErrorCode
            ErrorMessage = $COMHijacking.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("WCComHijacking")) {
        $COMHijacking = Get-COMHijacking
        $Output += [PSCustomObject]@{
            Name         = "WCComHijacking"
            DisplayName  = "WindowsConfiguration COM hijacking"
            Description  = "Checks if COM is hijacked."
            Score        = $COMHijacking.Score
            ResultData   = $COMHijacking.Result
            RiskScore    = 80
            ErrorCode    = $COMHijacking.ErrorCode
            ErrorMessage = $COMHijacking.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("WCTimeProvHijacking")) {
        $timeProviderHijacking = Get-vlTimeProviderHijacking
        $Output += [PSCustomObject]@{
            Name         = "WCTimeProvHijacking"
            DisplayName  = "WindowsConfiguration time provider hijacking"
            Description  = "Checks if the time provider is hijacked."
            Score        = $timeProviderHijacking.Score
            ResultData   = $timeProviderHijacking.Result
            RiskScore    = 80
            ErrorCode    = $timeProviderHijacking.ErrorCode
            ErrorMessage = $timeProviderHijacking.ErrorMessage
        }
    }

    <#
    TODO: Add a good log parsing logic to check for "corrupt" or "repaired" in CBS.log
    if ($params.Contains("all") -or $params.Contains("persistancecheck")) {
        $persistancecheck = Get-vlWindowsPersistanceCheck
        $Output += [PSCustomObject]@{
            Name         = "WindowsConfiguration - persistancecheck"
            Score        = $persistancecheck.Score
            ResultData   = $persistancecheck.Result
            RiskScore    = 80
            ErrorCode    = $persistancecheck.ErrorCode
            ErrorMessage = $persistancecheck.ErrorMessage
        }
    }
    #>   
    
    return $output
}

Write-Host (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)