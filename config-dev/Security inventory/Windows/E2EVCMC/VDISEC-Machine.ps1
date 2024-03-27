# Define the path to your CSV file
#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force


$global:auditPolicyData = $null
$global:securityTemplateData = $null

function Invoke-ParseIniFile {
    param (
        [string]$Path
    )

    $iniContent = @{}
    $currentSection = $null

    # Check if the file exists
    if (-not (Test-Path $Path)) {
        Write-Error "File '$Path' not found."
        return $null
    }

    # Read the file line by line
    Get-Content -Path $Path | ForEach-Object {
        $line = $_.Trim()

        # Check if the line is a section
        if ($line.StartsWith("[") -and $line.EndsWith("]")) {
            $currentSection = $line.Substring(1, $line.Length - 2)
            $iniContent[$currentSection] = @{}
        }
        elseif ($line -match "^\s*([^#;=]+?)\s*=\s*(.*?)\s*$") {
            # Lines with key=value (ignores spaces around key and value and lines starting with # or ;)
            $key = $matches[1]
            $value = $matches[2]

            if ($null -ne $currentSection) {
                $iniContent[$currentSection][$key] = $value
            }
            else {
                $iniContent[$key] = $value
            }
        }
    }

    return $iniContent
}

function Get-IniValue {
    param (
        [hashtable]$IniContent,
        [string]$Section,
        [string]$Key,
        [string]$DefaultValue
    )

    if ($IniContent.ContainsKey($Section)) {
        if ($IniContent[$Section].ContainsKey($Key)) {
            return $IniContent[$Section][$Key]
        }
    }

    return $DefaultValue
}


function Invoke-CleanTmpFolder {
    # Path to the tmp folder
    $tmpFolderPath = Join-Path -Path $PSScriptRoot -ChildPath "tmp"

    # Check if the tmp folder exists
    if (Test-Path -Path $tmpFolderPath) {
        # Delete the contents of the tmp folder
        Get-ChildItem -Path $tmpFolderPath -Recurse | Remove-Item -Force -Recurse
    }
    else {
        # Create the tmp folder if it does not exist
        New-Item -Path $tmpFolderPath -ItemType Directory | Out-Null
    }
}

function Export-SecEditConfig {
    # Path to the tmp folder
    $tmpFolderPath = Join-Path -Path $PSScriptRoot -ChildPath "tmp"

    # The path where the security settings will be exported
    $exportPath = Join-Path -Path $tmpFolderPath -ChildPath "secedit_export.cfg"

    # Export the security settings and check if the export was successful
    secedit /export /cfg $exportPath > $null

    # check if the export was successful
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to export security settings."
    }
}

function Export-AuditPolicy {
    # Path to the tmp folder
    $tmpFolderPath = Join-Path -Path $PSScriptRoot -ChildPath "tmp"

    # The path where the audit policy will be exported
    $exportPath = Join-Path -Path $tmpFolderPath -ChildPath "audit_policy.csv"

    # Export the audit policy
    auditpol /get /category:* /r > $exportPath
}

# Function to validate registry data
function Test-RegistryData {
    param (
        $Hive,
        $Path,
        $ValueName,
        $ExpectedData
    )

    # Construct the full registry path
    $fullPath = "${Hive}:\${Path}"

    # Check if the registry path exists
    if (Test-Path -Path $fullPath) {
        # Retrieve the registry item
        $registryItem = Get-ItemProperty -Path $fullPath

        # Check if the registry value exists
        if ($registryItem.PSObject.Properties.Name -contains $ValueName) {
            # Compare the actual registry data with the expected data from the CSV
            if ($registryItem.$ValueName -eq $ExpectedData) {
                return $ExpectedData
            }
            else {
                return $registryItem.$ValueName
            }
        }
        else {
            return "N/A"
        }
    }
    else {
        return "N/A"
    }
}

function Invoke-AuditPolicy {
    param (
        [PSCustomObject]$row
    )

    $subcategory = $row.'Registry Key'

    # Find the matching audit policy in the loaded CSV data
    $matchingPolicy = $global:auditPolicyData | Where-Object { $_.Subcategory -eq $subcategory }

    if ($matchingPolicy) {
        return $matchingPolicy.'Inclusion Setting'
    }

    if ($row.'Policy-Setting' -eq "[[Empty]]") {
        return $row.'Policy-Setting'
    }

    return "N/A"
}

function Invoke-SecurityTemplate {
    param (
        [PSCustomObject]$row
    )

    $header = $row.'Policy Group or Registry Key'
    $key = $row.'Registry Key'

    $value = Get-IniValue -IniContent $global:securityTemplateData -Section $header -Key $key -DefaultValue "N/A"

    # Check if we expect an empty value
    if ($value -eq "N/A" -and $row.'Policy-Setting' -eq "[[Empty]]") {
        return $row.'Policy-Setting'
    }

    return $value
}

function Invoke-ProcessPolicyFile {
    param (
        [string]$CsvPath,
        [int]$BatchSize,
        [int]$SkipTierGT,
        [string]$Delimiter
    )

    # Import the CSV file - assuming the delimiter is a semicolon
    $csvData = Import-Csv -Path $CsvPath -Delimiter $Delimiter

    $ScoreSum = 0
    $NumProcessed = 0
    $riskScore = 80
    $result = @()

    # Process the CSV data
    $missmatchCount = 0
    $batchResult = @()
    foreach ($row in $csvData) {

        # Check if the row has a risk tier and if it is greater than the skip tier 1 is the highest risk tier and 3 is the lowest
        if ($row.'Risk Tier' -gt $SkipTierGT ) {
            # Risk-Tier is greater than 1. Skipping row.
            continue
        }

        # Define the hive based on the Policy-Type
        $hive = ""
        if ($row.'Policy Type' -eq "HKLM") {
            $hive = "HKLM"
        }
        elseif ($row.'Policy Type' -eq "HKCU") {
            # we are doing machine only in this test
            continue
        }
        elseif ($row.'Policy Type' -eq "Audit Policy") {

            $auditPolicy = Invoke-AuditPolicy -row $row

            if ($auditPolicy -eq "N/A" -or $auditPolicy -ne $row.'Policy-Setting') {
                $ScoreSum += (10 - [float]$row.'Weight'.Replace(',', '.'))

                $auditTest = [PSCustomObject]@{
                    'Policy-Type'   = $row.'Policy Type'
                    'Key'           = $row.'Policy Group or Registry Key'
                    'Value-Name'    = $row.'Registry Key'
                    'Expected-Data' = $row.'Policy-Setting'
                    'Actual-Data'   = $auditPolicy
                }

                $batchResult += $auditTest
                $missmatchCount++

                if ($missmatchCount -ge $BatchSize) {

                    $Score = [Math]::Round($ScoreSum / $NumProcessed, 1)
                    # Create a New-vlResultObject for the current batch and add it to the result array
                    $batchResultObject = New-vlResultObject -result $batchResult -score $Score -riskScore $riskScore
                    $result += $batchResultObject

                    # Reset the batch variables
                    $batchResult = @()
                    $missmatchCount = 0

                    # Reset the score sum
                    $ScoreSum = 0
                    $NumProcessed = 0
                }
            }
            else {
                $ScoreSum += 10
            }

            $NumProcessed++

            continue
        }
        elseif ($row.'Policy Type' -eq "Security Template") {

            $securityTemplate = Invoke-SecurityTemplate -row $row

            if ($securityTemplate -eq "N/A" -or $securityTemplate -ne $row.'Registry-Value') {
                $ScoreSum += (10 - [float]$row.'Weight'.Replace(',', '.'))

                $secTest = [PSCustomObject]@{
                    'Policy-Type'   = $row.'Policy Type'
                    'Key'           = $row.'Policy Group or Registry Key'
                    'Value-Name'    = $row.'Registry Key'
                    'Expected-Data' = $row.'Policy-Setting'
                    'Actual-Data'   = $securityTemplate
                }

                $batchResult += $secTest
                $missmatchCount++

                if ($missmatchCount -ge $BatchSize) {

                    $Score = [Math]::Round($ScoreSum / $NumProcessed, 1)
                    # Create a New-vlResultObject for the current batch and add it to the result array
                    $batchResultObject = New-vlResultObject -result $batchResult -score $Score -riskScore $riskScore
                    $result += $batchResultObject

                    # Reset the batch variables
                    $batchResult = @()
                    $missmatchCount = 0

                    # Reset the score sum
                    $ScoreSum = 0
                    $NumProcessed = 0
                }
            }
            else {
                $ScoreSum += 10
            }

            $NumProcessed++

            continue
        }
        else {
            # Unknown Policy-Type value: $($row.'Policy-Type'). Skipping row.
            continue
        }

        $path = $row.'Policy Group or Registry Key'
        $valueName = $row.'Registry Key'
        $expectedData = $row.'Registry-Value'
        $y = Test-RegistryData -Hive $hive -Path $path -ValueName $valueName -ExpectedData $expectedData

        if ($y -ne $expectedData) {
            $ScoreSum += (10 - [float]$row.'Weight'.Replace(',', '.'))

            $regtest = [PSCustomObject]@{
                'Policy-Type'   = $row.'Policy Type'
                'Key'           = $path
                'Value-Name'    = $valueName
                'Expected-Data' = $expectedData
                'Actual-Data'   = $y
            }

            $batchResult += $regtest
            $missmatchCount++

            if ($missmatchCount -ge $BatchSize) {

                $Score = [Math]::Round($ScoreSum / $NumProcessed, 1)
                # Create a New-vlResultObject for the current batch and add it to the result array
                $batchResultObject = New-vlResultObject -result $batchResult -score $Score -riskScore $riskScore
                $result += $batchResultObject

                # Reset the batch variables
                $batchResult = @()
                $missmatchCount = 0

                # Reset the score sum
                $ScoreSum = 0
                $NumProcessed = 0
            }
        }
        else {
            $ScoreSum += 10
        }

        $NumProcessed++
    }

    # Check if there are any remaining items in the batch
    if ($batchResult.Count -gt 0) {
        $Score = [Math]::Round($ScoreSum / $NumProcessed, 1)

        # Create a New-vlResultObject for the remaining batch and add it to the result array
        $batchResultObject = New-vlResultObject -result $batchResult -score $Score -riskScore $riskScore
        $result += $batchResultObject
    }

    return $result
}

function Get-vlVDISECMemberServer2022 {
    $params = if ($global:args) { $global:args } else { "all" }
    $params = $params | ForEach-Object { $_.ToLower() }

    $Output = @()

    try {
        # Clean the tmp folder or create it if it does not exist
        Invoke-CleanTmpFolder

        # Export security settings
        Export-SecEditConfig

        # Export audit policy
        Export-AuditPolicy

        # Load Audit Policy settings
        $global:auditPolicyData = Import-Csv -Path "$PSScriptRoot\tmp\audit_policy.csv" | Where-Object { $_ -ne $null -and $_.Subcategory -ne "" }

        # Load Security Template settings, format is cfg file
        $global:securityTemplateData = Invoke-ParseIniFile -Path "$PSScriptRoot\tmp\secedit_export.cfg"

        # first load Policy\settings.json
        $settings = Get-Content -Path "$PSScriptRoot\Policies\settings.json" -Raw | ConvertFrom-Json

        $settings | ForEach-Object {
            $csvName = $_.FileName
            $delimiter = $_.Delimiter
            $dashboardName = $_.DashboardName
            $batchSize = $_.BatchSize
            $hasWeight = $_.HasWeight
            $hasRiskTier = $_.HasRiskTier

            $skipTierGT = 4 # Risk tier is from 1 to 3

            if ($hasRiskTier -eq $true) {
                $skipTierGT = $_.SkipTierGT
            }

            $result = Invoke-ProcessPolicyFile -CsvPath "$PSScriptRoot\Policies\$csvName" `
                -BatchSize $batchSize `
                -HasWeight $hasWeight `
                -HasRiskTier $hasRiskTier `
                -SkipTierGT $skipTierGT `
                -Delimiter $delimiter

            # loop through the result and add it to the output
            $index = 1
            foreach ($item in $result) {
                $Output += [PSCustomObject]@{
                    Name         = "$($dashboardName)_$index"
                    DisplayName  = "$($dashboardName)_$index"
                    Description  = ""
                    Score        = $item.Score
                    ResultData   = $item.Result
                    RiskScore    = $item.RiskScore
                    ErrorCode    = $item.ErrorCode
                    ErrorMessage = $item.ErrorMessage
                }
                $index++
            }
        }

        # Clean the tmp folder
        Invoke-CleanTmpFolder

        return $output

    }
    catch {
        Write-Error $_.Exception.Message
    }
}


try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
    $OutputEncoding = [System.Text.Encoding]::UTF8
}


# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlVDISECMemberServer2022 | ConvertTo-Json -Compress)
