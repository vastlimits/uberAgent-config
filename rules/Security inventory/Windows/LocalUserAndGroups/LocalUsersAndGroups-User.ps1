
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

function Get-vlIsLocalAdmin {
    <#
    .SYNOPSIS
        Function that checks if the user is a local admin.
    .DESCRIPTION
        Function that checks if the user is a local admin.
    .LINK
        https://uberagent.com
        
    .OUTPUTS
        If the user is a local admin, the script will return a vlResultObject with the IsLocalAdmin property set to true.
        If the user is not a local admin, the script will return a vlResultObject with the IsLocalAdmin property set to false.

    .EXAMPLE
        Get-vlIsLocalAdmin
    #>

    try {
        #checks if use has claim object S-1-5-32-544 (local admin group)
        $isLocalAdmin = [Security.Principal.WindowsIdentity]::GetCurrent().Claims.Value.Contains('S-1-5-32-544')
        if($isLocalAdmin) {
            $result = [PSCustomObject]@{
                IsLocalAdmin = $true
            }

            return New-vlResultObject -result $result -score 3
        }
        else {
            $result = [PSCustomObject]@{
                IsLocalAdmin = $false
            }
            return New-vlResultObject -result $result -score 10
        }
    }
    catch {
        return New-vlErrorObject($result)
    }
}


function Get-vlGetUserEnrolledFactors() {
    <#
    .SYNOPSIS
        Function that returns the user's enrolled bio factors.
    .DESCRIPTION
        Function that returns the user's enrolled bio factors.
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the Windows Hello is enabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to true.
        If the Windows Hello is disabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to false.
    .NOTES
        https://learn.microsoft.com/en-us/windows/win32/api/winbio/nf-winbio-winbiogetenrolledfactors
        WinBioGetEnrolledFactors

        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\S-1-12-1-*
    .EXAMPLE
        Get-vlGetUserEnrolledFactors
    #>
    
    $winBioBasePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio"
    
    if (-not (Test-Path -Path $winBioBasePath)) {
        return [PSCustomObject]@{
            WinBioAvailable = $false
            WinBioUsed      = $false
        }   
    }

    $currentUserSID = (whoami /user /fo csv | convertfrom-csv).SID

    if (-not (Test-Path -Path ($winBioBasePath + "\AccountInfo\" + $currentUserSID))) {
        return [PSCustomObject]@{
            WinBioAvailable = $true
            WinBioUsed      = $false
        }   
    }

    $enroledFactors = Get-vlRegValue -Hive "HKLM" -Path ("SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\" + $currentUserSID) -Value "EnrolledFactors"

    # iterate over [WinBioStatus].GetEnumNames() and check if the bit is set. If bit is set, save matching enum names in array $enroleFactors
    $enroledFac = @()
    foreach ($factor in [WinBioStatus].GetEnumNames()) {
        if ($enroledFactors -band [WinBioStatus]::$factor) {
            $enroledFac += $factor
        }
    }

    return [PSCustomObject]@{
        WinBioAvailable      = $true
        WinBioUsed           = $true
        WinBioEnroledFactors = $enroledFac
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
    .NOTES
        https://learn.microsoft.com/en-us/windows/win32/api/winbio/nf-winbio-winbiogetenrolledfactors
        WinBioGetEnrolledFactors

        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo\S-1-12-1-2792295418-1230826404-2486600877-521991098
    .EXAMPLE
        Get-vlWindowsHelloStatusLocalUser
    #>


    # Get currently logged on user's SID
    $currentUserSID = (whoami /user /fo csv | convertfrom-csv).SID

    # Registry path to credential provider belonging for the PIN. A PIN is required with Windows Hello
    $registryItems = Get-vlRegSubkeys2 -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}"
    if (-not $registryItems ) {
        $result = [PSCustomObject]@{
            WindowsHelloEnabled = $false
        }

        return New-vlResultObject -result $result -score 7
    }
    if (-NOT[string]::IsNullOrEmpty($currentUserSID)) {

        $enroledFactors = Get-vlGetUserEnrolledFactors

        if ($enroledFactors.WinBioAvailable -and $enroledFactors.WinBioUsed) {
            $enroledFactors = $enroledFactors.WinBioEnroledFactors
        }
        else {
            $enroledFactors = @()
        }

        # If multiple SID's are found in registry, look for the SID belonging to the logged on user
        if ($registryItems.GetType().IsArray) {
            # LogonCredsAvailable needs to be set to 1, indicating that the PIN credential provider is in use
            if ($registryItems.Where({ $_.PSChildName -eq $currentUserSID }).LogonCredsAvailable -eq 1) {
                $result = [PSCustomObject]@{
                    WindowsHelloEnabled = $true
                    EnrolledFactors     = $enroledFactors
                }

                return New-vlResultObject -result $result -score 10    
            }
            else {
                $result = [PSCustomObject]@{
                    WindowsHelloEnabled = $false
                    EnrolledFactors     = $enroledFactors
                }

                return New-vlResultObject -result $result -score 7    
            }
        }
        else {
            if (($registryItems.PSChildName -eq $currentUserSID) -AND ($registryItems.LogonCredsAvailable -eq 1)) {
                $result = [PSCustomObject]@{
                    WindowsHelloEnabled = $true
                    EnrolledFactors     = $enroledFactors
                }

                return New-vlResultObject -result $result -score 10    
            }
            else {
                $result = [PSCustomObject]@{
                    WindowsHelloEnabled = $false
                    EnrolledFactors     = $enroledFactors
                }

                return New-vlResultObject -result $result -score 7   
            } 
        }
    }
    else {
        return New-vlErrorObject("Not able to determine Windows Hello enrollment status")
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

    if ($params.Contains("all") -or $params.Contains("islocaladmin")) {
        $isLocalAdmin = Get-vlIsLocalAdmin
        $Output += [PSCustomObject]@{
            Name         = "islocaladmin"
            Score        = $isLocalAdmin.Score
            ResultData   = $isLocalAdmin.Result
            RiskScore    = 70
            ErrorCode    = $isLocalAdmin.ErrorCode
            ErrorMessage = $isLocalAdmin.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("userwinhellostatus")) {
        $windowsHelloStatus = Get-vlWindowsHelloStatusLocalUser
        $Output += [PSCustomObject]@{
            Name         = "userwinhellostatus"
            Score        = $windowsHelloStatus.Score
            ResultData   = $windowsHelloStatus.Result
            RiskScore    = 30
            ErrorCode    = $windowsHelloStatus.ErrorCode
            ErrorMessage = $windowsHelloStatus.ErrorMessage
        }
    }
    return $output
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlLocalUsersAndGroupsCheck | ConvertTo-Json -Compress)
