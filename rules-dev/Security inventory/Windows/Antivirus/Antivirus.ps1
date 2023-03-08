#Requires -RunAsAdministrator
#Requires -Version 3.0

. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#https://mcpforlife.com/2020/04/14/how-to-resolve-this-state-value-of-av-providers/
[Flags()] enum ProductState 
{
    Off         = 0x0000
    On          = 0x1000
    Snoozed     = 0x2000
    Expired     = 0x3000
}

[Flags()] enum SignatureStatus
{
    UpToDate     = 0x00
    OutOfDate    = 0x10
}

[Flags()] enum ProductOwner
{
    NonMs        = 0x000
    Windows      = 0x100
}

[Flags()] enum ProductFlags
{
   SignatureStatus = 0x000000F0
   ProductOwner    = 0x00000F00
   ProductState    = 0x0000F000
}

function Get-vlAntivirusStatus {
    <#
    .SYNOPSIS
        Get the status of the antivirus software
    .DESCRIPTION
        Get the status of the antivirus software
        This cmdlet is only available on the Windows platform.
        Get-WmiObject was added in PowerShell 3.0
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the status of the antivirus software
    .EXAMPLE
        Get-vlAntivirusStatus
    #>

    param (

    )

    process {
        try {
            $instances = Get-WmiObject -Class AntiVirusProduct -Namespace "root\SecurityCenter2"

            $riskScore = 100
            $score = 0
            $result = @()

            foreach ($instance in $instances) {
                $avEnabled = $([ProductState]::On.value__ -eq $($instance.productState -band [ProductFlags]::ProductState) )
                $avUp2Date = $([SignatureStatus]::UpToDate.value__ -eq $($instance.productState -band [ProductFlags]::SignatureStatus) )

                if($avEnabled -and $avUp2Date) {
                    $score = 10
                }elseif($avEnabled -and -not $avUp2Date) {
                    $score = 4
                }else 
                {
                    $score = 0
                }

                $result += [PSCustomObject]@{
                    AntivirusEnabled = $avEnabled
                    AntivirusName    = $instance.displayName
                    AntivirusUpToDate = $avUp2Date
                }
            }

            return New-vlResultObject -result $result -score $score -riskScore $riskScore
        }
        catch {
            return New-vlErrorObject($_)
        }
        finally {

        }

    }
    
}


function Get-vlDefenderStatus {
    <#
    .SYNOPSIS
        Get the status of the registrated antivirus
    .DESCRIPTION
        Get the status of the registrated antivirus using Get-MpComputerStatus from the Microsoft Antimalware API
    .NOTES
        The result will be converted to JSON and returend as a vlResultObject or vlErrorObject
        Requires min PowerShell 3.0 and the Microsoft Antimalware API
    .LINK
        https://uberagent.com
    .OUTPUTS
        A vlResultObject | vlErrorObject [psobject] containing the list of AMSI providers
    .EXAMPLE
        Get-vlAMSIProviders
    #>

    [CmdletBinding()]
    param (
        
    )

    process {
        try {
            $instances = Get-MpComputerStatus

            $result = [PSCustomObject]@{
                AMEngineVersion                 = $instances.AMEngineVersion
                AMServiceEnabled                = $instances.AMServiceEnabled
                AMServiceVersion                = $instances.AMServiceVersion
                AntispywareEnabled              = $instances.AntispywareEnabled
                AntivirusEnabled                = $instances.AntivirusEnabled
                AntispywareSignatureLastUpdated = $instances.AntispywareSignatureLastUpdated
                AntispywareSignatureVersion     = $instances.AntispywareSignatureVersion
                AntivirusSignatureLastUpdated   = $instances.AntivirusSignatureLastUpdated
                QuickScanSignatureVersion       = $instances.QuickScanSignatureVersion
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

function Get-vlAntivirusCheck {
    <#
    .SYNOPSIS
        Function that performs the antivirus check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the antivirus check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlAntivirusCheck -amsi -avStatus
    #>

    #set $params to $global:args or if empty default "all"
    $params = if ($global:args) { $global:args } else { "all" }
    $params = $params | ForEach-Object { $_.ToLower() }

    $Output = @()

    if ($params.Contains("all") -or $params.Contains("avstatus")) {
        $avStatus = Get-vlAntivirusStatus
        $Output += [PSCustomObject]@{
            Name       = "avStatus"
            Score      = $avStatus.Score
            ResultData = $avStatus.Result
            RiskScore  = $avStatus.RiskScore
            ErrorCode      = $avStatus.ErrorCode
            ErrorMessage   = $avStatus.ErrorMessage
        }
    }

    <#
    if ($params.Contains("all") -or $params.Contains("defenderstatus")) {
        $defenderStatus = Get-vlDefenderStatus
        $Output += [PSCustomObject]@{
            Name       = "defenderStatus"
            Score      = 0
            ResultData = $defenderStatus.Result
            RiskScore  = 100
            ErrorCode      = $defenderStatus.ErrorCode
            ErrorMessage   = $defenderStatus.ErrorMessage
        }
    }
    #>
    
    Write-Output $output
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlAntivirusCheck | ConvertTo-Json -Compress)