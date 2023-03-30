
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

function Get-vlPowerShellV2Status {
    <#
    .SYNOPSIS
        Performs a check if PowerShell V2 is installed on the system
    .DESCRIPTION
        Performs a check if PowerShell V2 is installed on the system
    .LINK
        https://uberagent.com
    .NOTES
        This function requires elevated privilegs
        https://www.tenforums.com/tutorials/111654-enable-disable-windows-powershell-2-0-windows-10-a.html
    .OUTPUTS
        A [psobject] containing the status of the PowerShell V2 installation
    .EXAMPLE
        Get-vlPowerShellV2Status
    #>

    param (

    )

    process {
        try {
            #check if PowerShell V2 is installed on the system
            $installationStatus = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

            $result = [PSCustomObject]@{
                PowerShellV2Enabled = ($installationStatus.State -eq "Enabled")
            }

            if ($result.PowerShellV2Enabled) {
                return New-vlResultObject -result $result -score 4
            }
            else {
                return New-vlResultObject -result $result -score 10
            }
        }
        catch {

            return New-vlErrorObject($_)
        }
        finally {

        }

    }

}

function Get-vlPowerShellCL {
    <#
    .SYNOPSIS
        Checks the current PowerShell LanguageMode
    .DESCRIPTION
        Checks the current PowerShellLanguageMode
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell LanguageMode
    .NOTES
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.3
    .EXAMPLE
        Get-vlPowerShellCL
    #>

    param ()

    process {
        try {
            $result = [PSCustomObject]@{
                LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
            }

            return New-vlResultObject -result $result
        }
        catch {

            return New-vlErrorObject($_)
        }
        finally {

        }
    }

}

function Get-vlPowerShellVersion {
    <#
    .SYNOPSIS
        Checks the current PowerShell version
    .DESCRIPTION
        Checks the current PowerShell version
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell version
    .EXAMPLE
        Get-vlPowerShellVersion
    #>

    param ()

    process {
        try {
            $result = [PSCustomObject]@{
                Version = $PSVersionTable.PSVersion.ToString()
            }

            return New-vlResultObject -result $result
        }
        catch {

            return New-vlErrorObject($_)
        }
        finally {

        }
    }

}

Function Get-vlPowerShellRemotingStatus {
    <#
    .SYNOPSIS
        Checks the current PowerShell remoting status
    .DESCRIPTION
        Checks the current PowerShell remoting status
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell remoting status
    .EXAMPLE
        Get-vlPowerShellRemotingStatus
    #>

    try {
        $serviceStatus = Get-Service -Name WinRM | Select-Object -ExpandProperty Status

        #if the service is not running, remoting is disabled
        if ($serviceStatus -ne "Running") {
            $result = [PSCustomObject]@{
                RemotingEnabled = $false
                JEAEnabled      = $false
            }

            return New-vlResultObject -result $result -score 10 -riskScore 50
        }

        # Try to open a session to localhost
        $session = New-PSSession -ComputerName localhost

        # Close the session
        Remove-PSSession $session

        # Check if JEA is enabled
        $JEAState = Get-vlJEACheck

        # If the session is opened, remoting is enabled
        $result = [PSCustomObject]@{
            RemotingEnabled = $true
            JEAEnabled      = $JEAState
        }

        if ($JEAState) {
            return New-vlResultObject -result $result -score 8 -riskScore 30
        }
        else {
            return New-vlResultObject -result $result -score 4 -riskScore 50
        }
    }
    catch {
        $result = [PSCustomObject]@{
            RemotingEnabled = $false
            JEAEnabled      = $false
        }
        # If the session cannot be opened, remoting is disabled
        return New-vlResultObject -result $result -score 10 -riskScore 30
    }
}

function Get-vlPowerShellExecutionPolicy {
    <#
    .SYNOPSIS
        Checks the current PowerShell execution policy for the current user
    .DESCRIPTION
        Checks the current PowerShell execution policy for the current user
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell execution policy
    .EXAMPLE
        Get-vlPowerShellExecutionPolicy
    #>

    param ()

    process {
        try {
            $result = [PSCustomObject]@{
                ExecutionPolicyLM = "Undefined"
                ExecutionPolicyCU = "Undefined"
            }

            $policys = Get-ExecutionPolicy -List
            $highestPolicy = "Undefined"

            # go from lowest to highest
            # first check LocalMachine policy
            $policy = $policys | Where Scope -eq "LocalMachine"

            if ($policy.ExecutionPolicy -ne "Undefined") {
                $highestPolicy = "LocalMachine"
                $result.ExecutionPolicyLM = $policy.ExecutionPolicy.ToString()
            }

            # check CurrentUser policy
            $policy = $policys | Where Scope -eq "CurrentUser"

            if ($policy.ExecutionPolicy -ne "Undefined") {
                $highestPolicy = "CurrentUser"
                $result.ExecutionPolicyCU = $policy.ExecutionPolicy.ToString()
            }

            # check UserPolicy policy
            $policy = $policys | Where Scope -eq "UserPolicy"

            if ($policy.ExecutionPolicy -ne "Undefined") {
                $highestPolicy = "UserPolicy"
                $result.ExecutionPolicyCU = $policy.ExecutionPolicy.ToString()
            }

            # check MachinePolicy policy
            $policy = $policys | Where Scope -eq "MachinePolicy"

            if ($policy.ExecutionPolicy -ne "Undefined") {
                $highestPolicy = "MachinePolicy"
                $result.ExecutionPolicyLM = $policy.ExecutionPolicy.ToString()
            }

            $LMrisk = 80
            $CUrisk = 80
            $LMLevel = 2
            $CULevel = 2

            # Level 0: Unrestricted
            # Level 1: Bypass
            # Level 2: RemoteSigned
            # Level 3: AllSigned
            # Level 4: Restricted
            # Level 5: Undefined

            # check $result.ExecutionPolicyLM and $result.ExecutionPolicyCU and set $LMLevel and $CULevel accordingly
            switch ($result.ExecutionPolicyLM) {
                "Unrestricted" {
                    $LMLevel = 2
                    $LMrisk = 80
                }
                "Bypass" {
                    $LMLevel = 2
                    $LMrisk = 80
                }
                "RemoteSigned" {
                    $LMLevel = 6
                    $LMrisk = 40
                }
                "AllSigned" {
                    $LMLevel = 8
                    $LMrisk = 20
                }
                "Restricted" {
                    $LMLevel = 10
                    $LMrisk = 20
                }
                "Undefined" {
                    $LMLevel = 10
                    $LMrisk = 20
                }
            }

            switch ($result.ExecutionPolicyCU) {
                "Unrestricted" {
                    $CULevel = 2
                    $CUrisk = 80
                }
                "Bypass" {
                    $CULevel = 2
                    $CUrisk = 80
                }
                "RemoteSigned" {
                    $CULevel = 6
                    $CUrisk = 40
                }
                "AllSigned" {
                    $CULevel = 8
                    $CUrisk = 20
                }
                "Restricted" {
                    $CULevel = 10
                    $CUrisk = 20
                }
                "Undefined" {
                    $CULevel = 10
                    $CUrisk = 20
                }
            }

            if ($highestPolicy -eq "MachinePolicy") {
                return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
            }
            elseif ($highestPolicy -eq "UserPolicy") {
                return New-vlResultObject -result $result -score $CULevel -riskScore $CUrisk
            }
            elseif ($highestPolicy -eq "CurrentUser") {
                return New-vlResultObject -result $result -score $CULevel -riskScore $CUrisk
            }
            elseif ($highestPolicy -eq "LocalMachine") {
                return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
            }

            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            <#
                Work Station (1)
                Domain Controller (2)
                Server (3)
            #>

            # If the execution policy in all scopes is Undefined, the effective execution policy is Restricted for Windows clients and RemoteSigned for Windows Server.
            if ($osInfo.ProductType -eq 1) {
                return New-vlResultObject -result $result -score 10 -riskScore 0
            }
            else {
                return New-vlResultObject -result $result -score 6 -riskScore 40
            }
        }
        catch {

            return New-vlErrorObject($_)
        }
        finally {

        }
    }

}

Function Get-vlPowerShellLoggingTranscriptionStatus {
    <#
    .SYNOPSIS
        Checks the current transcription logging status
    .DESCRIPTION
        Checks the current transcription logging status by checking the registry and group policy
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current transcription logging status
    .EXAMPLE
        Get-vlPowerShellLoggingTranscriptionStatus
    #>

    $result = [PSCustomObject]@{
        Registry    = $false
        GroupPolicy = $false
    }

    try {
        $transcription = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Value "EnableTranscripting"
        if ( $transcription -eq 1) {
            $result.Registry = $true
        }

        $transcription = (Get-GPRegistryValue -Name "EnableTranscripting" -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell").Value
        if ($transcription -eq 1) {
            $result.GroupPolicy = $true
        }
    }
    catch {

    }

    return $result
}

Function Get-vlPowerShellLoggingScriptBlockStatus {
    <#
    .SYNOPSIS
        Checks the current script block logging status
    .DESCRIPTION
        Checks the current script block logging status by checking the registry and group policy
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current script block logging status
    .EXAMPLE
        Get-vlPowerShellLoggingScriptBlockStatus
    #>


    $result = [PSCustomObject]@{
        Registry    = $false
        GroupPolicy = $false
    }

    try {
        $scriptBlockLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Value "EnableScriptBlockLogging"
        if ($scriptBlockLogging -eq 1) {
            $result.Registry = $true
        }

        $scriptBlockLogging = (Get-GPRegistryValue -Name "EnableScriptBlockLogging" -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell").Value
        if ($scriptBlockLogging -eq 1) {
            $result.GroupPolicy = $true
        }
    }
    catch {

    }

    return $result
}

Function Get-vlPowerShellLoggingModuleLogging {
    <#
    .SYNOPSIS
        Checks the current script module logging status
    .DESCRIPTION
        Checks the current script module logging status by checking the registry and group policy
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current script block logging status
    .EXAMPLE
        Get-vlPowerShellLoggingModuleLogging
    #>

    $result = [PSCustomObject]@{
        Registry    = $false
        GroupPolicy = $false
    }

    try {
        $scriptBlockLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Value "EnableModuleLogging"
        if ($scriptBlockLogging -eq 1) {
            $result.Registry = $true
        }

        $scriptBlockLogging = (Get-GPRegistryValue -Name "EnableModuleLogging" -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell").Value
        if ($scriptBlockLogging -eq 1) {
            $result.GroupPolicy = $true
        }
    }
    catch {

    }

    return $result
}

function Get-vlPowerShellLogging {
    <#
    .SYNOPSIS
        Checks the current PowerShell logging settings
    .DESCRIPTION
        Checks the current PowerShell logging settings by reading the registry
    .LINK
        https://uberagent.com
        https://adamtheautomator.com/powershell-logging-2/
        https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
    .OUTPUTS
        A [psobject] containing the current PowerShell logging settings
    .EXAMPLE
        Get-vlPowerShellLogging
    #>

    param ()

    process {
        try {
            $transcriptionStatus = Get-vlPowerShellLoggingTranscriptionStatus
            $scriptBlockStatus = Get-vlPowerShellLoggingScriptBlockStatus
            $moduleLoggingStatus = Get-vlPowerShellLoggingModuleLogging

            $score = 10
            $result = [PSCustomObject]@{
                Transcription = $transcriptionStatus
                ScriptBlock   = $scriptBlockStatus
                ModuleLogging = $moduleLoggingStatus
            }

            if (($transcriptionStatus.Registry -eq $false -and $transcriptionStatus.GroupPolicy -eq $false) -and ($scriptBlockStatus.Registry -eq $false -and $scriptBlockStatus.GroupPolicy -eq $false) -and ($moduleLoggingStatus.Registry -eq $false -and $moduleLoggingStatus.GroupPolicy -eq $false)) {
                $score = 8
            }
            elseif (($transcriptionStatus.Registry -eq $true -or $transcriptionStatus.GroupPolicy -eq $true ) -and ($scriptBlockStatus.Registry -eq $true -or $scriptBlockStatus.GroupPolicy -eq $true ) -and ($moduleLoggingStatus.Registry -eq $true -or $moduleLoggingStatus.GroupPolicy -eq $true )) {
                $score = 10
            }
            else {
                $score = 9
            }

            return New-vlResultObject -result $result -score $score
        }
        catch {

            return New-vlErrorObject($_)
        }
        finally {

        }
    }

}

Function Get-vlJEACheck {
    <#
    .SYNOPSIS
        Checks if Just Enough Administration (JEA) is enabled
    .DESCRIPTION
        Checks if Just Enough Administration (JEA) is enabled
    .LINK
        https://uberagent.com
    .OUTPUTS
        Returns true if JEA is enabled, false otherwise
    .EXAMPLE
        Get-vlJEACheck
    #>

    param ()

    process {
        # check if WinRM service is running
        $winrm = Get-Service -Name WinRM

        if ($winrm.Status -ne "Running") {
            return $false
        }

        # check if there are any JEA sessions
        $jeaSessions = Get-PSSessionConfiguration | Where-Object { $_.RunAsVirtualAccount -eq $true }
        if ($jeaSessions.Count -eq 0) {
            return $false
        }
        else {
            return $true
        }
    }
}


function Get-vlPowerShellCheck {
    #Start-Sleep -Seconds 15
    <#
    .SYNOPSIS
        Function that performs the PowerShell check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the PowerShell check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlPowerShellCheck
    #>

    #set $params to $global:args or if empty default "all"
    $params = if ($global:args) { $global:args } else { "all" }
    $params = $params | ForEach-Object { $_.ToLower() }

    $Output = @()

    if ($params.Contains("all") -or $params.Contains("PSV2")) {
        $powerShellV2 = Get-vlPowerShellV2Status
        $Output += [PSCustomObject]@{
            Name         = "PSV2"
            DisplayName  = "PowerShell V2"
            Description  = "Checks if PowerShell V2 is enabled"
            Score        = $powerShellV2.Score
            ResultData   = $powerShellV2.Result
            RiskScore    = 60
            ErrorCode    = $powerShellV2.ErrorCode
            ErrorMessage = $powerShellV2.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("PSRemoting")) {
        $powerShellRemoting = Get-vlPowerShellRemotingStatus
        $Output += [PSCustomObject]@{
            Name         = "PSRemoting"
            DisplayName  = "PowerShell Remoting"
            Description  = "Checks if PowerShell remoting is enabled"
            Score        = $powerShellRemoting.Score
            ResultData   = $powerShellRemoting.Result
            RiskScore    = $powerShellRemoting.RiskScore
            ErrorCode    = $powerShellRemoting.ErrorCode
            ErrorMessage = $powerShellRemoting.ErrorMessage
        }
    }

    ## If CL is enabled, the test cannot be run
    if ($params.Contains("all") -or $params.Contains("PSCL")) {
        $powerShellMode = Get-vlPowerShellCL
        $Output += [PSCustomObject]@{
            Name         = "PSCL"
            DisplayName  = "PowerShell common language mode"
            Description  = "Checks if PowerShell Common Language Mode is enabled"
            Score        = 10
            ResultData   = $powerShellMode.Result
            RiskScore    = 0
            ErrorCode    = $powerShellMode.ErrorCode
            ErrorMessage = $powerShellMode.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("PSVersion")) {
        $powerShellMode = Get-vlPowerShellVersion
        $Output += [PSCustomObject]@{
            Name         = "PSVersion"
            DisplayName  = "PowerShell version"
            Description  = "The PowerShell version in use"
            Score        = 10
            ResultData   = $powerShellMode.Result
            RiskScore    = 0
            ErrorCode    = $powerShellMode.ErrorCode
            ErrorMessage = $powerShellMode.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("PSPolicy")) {
        $powerShellExecutionPolicy = Get-vlPowerShellExecutionPolicy
        $Output += [PSCustomObject]@{
            Name         = "PSPolicy"
            DisplayName  = "PowerShell policy"
            Description  = "Checks and evaluates the PowerShell Execution Policy"
            Score        = $powerShellExecutionPolicy.Score
            ResultData   = $powerShellExecutionPolicy.Result
            RiskScore    = $powerShellExecutionPolicy.RiskScore
            ErrorCode    = $powerShellExecutionPolicy.ErrorCode
            ErrorMessage = $powerShellExecutionPolicy.ErrorMessage
        }
    }

    if ($params.Contains("all") -or $params.Contains("PSLogging")) {
        $powerShellLogging = Get-vlPowerShellLogging
        $Output += [PSCustomObject]@{
            Name         = "PSLogging"
            DisplayName  = "PowerShell logging"
            Description  = "Checks if PowerShell Logging is enabled"
            Score        = $powerShellLogging.Score
            ResultData   = $powerShellLogging.Result
            RiskScore    = 20
            ErrorCode    = $powerShellLogging.ErrorCode
            ErrorMessage = $powerShellLogging.ErrorMessage
        }
    }

    Write-Output $output
}


# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlPowerShellCheck | ConvertTo-Json -Compress)