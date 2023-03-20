
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

function Get-vlUACState {
    <#
    .SYNOPSIS
        Function that checks if the UAC is enabled.
    .DESCRIPTION
        Function that checks if the UAC is enabled.
        This check is using the registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the UAC is enabled, the script will return a vlResultObject with the UACEnabled property set to true.
        If the UAC is disabled, the script will return a vlResultObject with the UACEnabled property set to false.
    .EXAMPLE
        Get-vlUACState
    #>

    try {
        $uac = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Value "EnableLUA"
        if ($uac.EnableLUA -eq 1) {
            $result = [PSCustomObject]@{
                UACEnabled = $true
            }

            return New-vlResultObject -result $result -score 10
        }
        else {
            $result = [PSCustomObject]@{
                UACEnabled = $false
            }

            return New-vlResultObject -result $result -score 4
        }
    }
    catch {
        return New-vlErrorObject($_)
    }
}

function Get-vlLAPSState {
    <#
    .SYNOPSIS
        Function that checks if the UAC is enabled.
    .DESCRIPTION
        Function that checks if the UAC is enabled.
        This check is using the registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the UAC is enabled, the script will return a vlResultObject with the UACEnabled property set to true.
        If the UAC is disabled, the script will return a vlResultObject with the UACEnabled property set to false.
    .EXAMPLE
        Get-vlUACState
    #>

    try {
        $laps = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft Services\AdmPwd" -Value "AdmPwdEnabled"
        if ($laps.AdmPwdEnabled -eq 1) {
            $result = [PSCustomObject]@{
                LAPSEnabled = $true
            }

            return New-vlResultObject -result $result -score 10
        }
        else {
            $result = [PSCustomObject]@{
                LAPSEnabled = $false
            }

            return New-vlResultObject -result $result -score 6
        }
    }
    catch {
        return New-vlErrorObject($_)
    }
}

function Get-vlSecrets {
    <#
    .SYNOPSIS
        Function that checks if LSA secrets are enabled.
    .DESCRIPTION
        Function that checks if LSA secrets are enabled.
        This check is using the registry key HKLM:\Security\Policy\Secrets
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the LSA secrets are enabled, the script will return a vlResultObject with the SecretsEnabled property set to true.
        If the LSA secrets are disabled, the script will return a vlResultObject with the SecretsEnabled property set to false.
    .EXAMPLE
        Get-vlSecrets
    #>

    try {
        $AdmPwdEnabled = Get-vlRegValue -Hive "HKLM" -Path "Security\Policy\Secrets" -Value ""
        if ($AdmPwdEnabled) {
            $result = [PSCustomObject]@{
                SecretsEnabled = $true
            }
            return New-vlResultObject -result $result -score 10
        }
        else {
            $result = [PSCustomObject]@{
                SecretsEnabled = $false
            }
            return New-vlResultObject -result $result -score 6
        }
    }
    catch {
        return New-vlErrorObject($_)
    }
}

function Get-vlLAPSSettings {
    <#
    .SYNOPSIS
        Function that returns the LAPS settings.
    .DESCRIPTION
        Function that returns the LAPS settings.
        This check is using the registry key HKLM:\Software\Policies\Microsoft Services\AdmPwd
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the LAPS is enabled, the script will return a vlResultObject with the following properties:
            LAPSEnabled
            LAPSAdminAccountName
            LAPSPasswordComplexity
            LAPSPasswordLength
            LAPSPasswordExpirationProtectionEnabled
        If the LAPS is disabled, the script will return a vlResultObject with the LAPSEnabled property set to false.
    .EXAMPLE
        Get-vlLAPSSettings
    #>

    try {
        $hkey = "Software\Policies\Microsoft Services\AdmPwd"
        $AdmPwdEnabled = Get-vlRegValue -Hive "HKLM" -Path $hkey -Value "AdmPwdEnabled"

        if ($AdmPwdEnabled -ne "") {
            $lapsAdminAccountName = Get-RegValue -Hive "HKLM" -Path $hkey "AdminAccountName"
            $lapsPasswordComplexity = Get-RegValue -Hive "HKLM" -Path $hkey "PasswordComplexity"
            $lapsPasswordLength = Get-RegValue -Hive "HKLM" -Path $hkey "PasswordLength"
            $lapsExpirationProtectionEnabled = Get-RegValue -Hive "HKLM" -Path $hkey "PwdExpirationProtectionEnabled"
    
            $lapsSettings = 
            [PSCustomObject]@{
                LAPSEnabled                             = $AdmPwdEnabled
                LAPSAdminAccountName                    = $lapsAdminAccountName
                LAPSPasswordComplexity                  = $lapsPasswordComplexity
                LAPSPasswordLength                      = $lapsPasswordLength
                LAPSPasswordExpirationProtectionEnabled = $lapsExpirationProtectionEnabled
            }
            return New-vlResultObject -result $lapsSettings -score 10
        }
        else {
            $lapsSettings = 
            [PSCustomObject]@{
                LAPSEnabled = $false
            }
            return New-vlResultObject -result $lapsSettings -score 6
        }
        
    }
    catch {
        return New-vlErrorObject($_)
    }
}

[Flags()] enum WinBioStatus {
    MULTIPLE = 0x00000001;
    FACIAL_FEATURES = 0x00000002;
    VOICE = 0x00000004;
    FINGERPRINT = 0x00000008;
    IRIS = 0x00000010;
    RETINA = 0x00000020;
    HAND_GEOMETRY = 0x00000040;
    SIGNATURE_DYNAMICS = 0x00000080;
    KEYSTROKE_DYNAMICS = 0x00000100;
    LIP_MOVEMENT = 0x00000200;
    THERMAL_FACE_IMAGE = 0x00000400;
    THERMAL_HAND_IMAGE = 0x00000800;
    GAIT = 0x00001000;
    SCENT = 0x00002000;
    DNA = 0x00004000;
    EAR_SHAPE = 0x00008000;
    FINGER_GEOMETRY = 0x00010000;
    PALM_PRINT = 0x00020000;
    VEIN_PATTERN = 0x00040000;
    FOOT_PRINT = 0x00080000;
    OTHER = 0x40000000;
    PASSWORD = 0x80000000;
}

function Get-vlMachineAvailableFactors() {
    <#
    .SYNOPSIS
        Function that returns the Machine Factors, that can be used.
    .DESCRIPTION
        Function that returns the Machine Factors, that can be used.
    .LINK
        https://uberagent.com
    .OUTPUTS
        Retruns if the Machine Factors are available and the name of the factors
    .NOTES        
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo
    .EXAMPLE
        Get-vlMachineAvailableFactors
    #>
    
    $winBioUsed = $false
    $winBioAccountInfoPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo"
    $winBioSensorInfoBasePath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo"
    
    if (-not (Test-Path -Path ("HKLM:\" + $winBioSensorInfoBasePath ))) {
        return [PSCustomObject]@{
            WinBioAvailable        = $false
            WinBioUsed             = $false
            WinBioAvailableFactors = @()
        }   
    }

    $bioUsers = Get-vlRegSubkeys -Hive "HKLM" -Path $winBioAccountInfoPath

    foreach ($bioUser in $bioUsers) {
        $bioUserValues = Get-vlRegValue -Hive "HKLM" -Path ($winBioAccountInfoPath + "\" + $bioUser) -Value "EnrolledFactors"

        if ($bioUserValues -and $bioUserValues -gt 0) {
            $winBioUsed = $true
        }
    }

    $availableFactors = Get-vlRegValue -Hive "HKLM" -Path $winBioSensorInfoBasePath -Value "AvailableFactors"

    # iterate over [WinBioStatus].GetEnumNames() and check if the bit is set. If bit is set, save matching enum names in array $availableFac
    $availableFac = @()
    foreach ($factor in [WinBioStatus].GetEnumNames()) {
        if ($availableFactors -band [WinBioStatus]::$factor) {
            $availableFac += $factor
        }
    }

    return [PSCustomObject]@{
        WinBioAvailable        = $true
        WinBioUsed             = $winBioUsed
        WinBioAvailableFactors = $availableFac
    }
    
}

function Get-vlWindowsHelloStatusLocalUser() {
    <#
    .SYNOPSIS
        Function that checks if Windows Hello is enabled.
    .DESCRIPTION
        Function that checks if Windows Hello is enabled.
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the Windows Hello is enabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to true.
        If the Windows Hello is disabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to false.
    .EXAMPLE
        Get-vlLAPSSettings
    #>

    try {
        $factors = Get-vlMachineAvailableFactors

        if($factors.WinBioAvailable -and $factors.WinBioUsed) {
            return New-vlResultObject -result $factors -score 10
        }
        else {
            return New-vlResultObject -result $factors -score 7
        }
    }
    catch {
        return New-vlErrorObject($_)
    }
}

function Get-vlLocalUsersAndGroupsCheck {
    <#
    .SYNOPSIS
        Function that performs the LocalUsersAndGroups check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the LocalUsersAndGroups check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlLocalUsersAndGroupsCheck -uacState -lapsState -secrets
    #>

    $params = if ($global:args) { $global:args } else { "all" }
    $params = $params | ForEach-Object { $_.ToLower() }
    
    $Output = @()

    if ($params.Contains("all") -or $params.Contains("uacstate")) {
        $uac = Get-vlUACState
        $Output += [PSCustomObject]@{
            Name       = "uacState"
            Score      = $uac.Score
            ResultData = $uac.Result
            RiskScore  = 60
            ErrorCode      = $uac.ErrorCode
            ErrorMessage   = $uac.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("lapsstate")) {
        $laps = Get-vlLAPSSettings
        $Output += [PSCustomObject]@{
            Name       = "lapsState"
            Score      = $laps.Score
            ResultData = $laps.Result
            RiskScore  = 40
            ErrorCode      = $laps.ErrorCode
            ErrorMessage   = $laps.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("secrets")) {
        $secrets = Get-vlSecrets
        $Output += [PSCustomObject]@{
            Name       = "secrets"
            Score      = $secrets.Score
            ResultData = $secrets.Result
            RiskScore  = 40
            ErrorCode      = $secrets.ErrorCode
            ErrorMessage   = $secrets.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("userwinhellostatus")) {
        $windowsHelloStatus = Get-vlWindowsHelloStatusLocalUser
        $Output += [PSCustomObject]@{
            Name       = "userwinhellostatus"
            Score      = $windowsHelloStatus.Score
            ResultData = $windowsHelloStatus.Result
            RiskScore  = 40
            ErrorCode      = $windowsHelloStatus.ErrorCode
            ErrorMessage   = $windowsHelloStatus.ErrorMessage
        }
    }
    return $output
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlLocalUsersAndGroupsCheck | ConvertTo-Json -Compress)
