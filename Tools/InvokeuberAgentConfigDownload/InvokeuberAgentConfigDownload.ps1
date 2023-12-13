#requires -Version 5

<#
.SYNOPSIS
Downloads the uberAgent configuration from a configurable GitHub branch, applies excludes and includes, creates a configuration archive, and copies the result to a target folder.

.PARAMETER Branch
The GitHub branch that should be cloned. A branch is equivalent to an uberAgent version. Mandatory parameter.

.PARAMETER TargetDirectory
Path the files should be copied to. Only full paths are supported. Do not use relative paths. Mandatory parameter.

.PARAMETER Excludes
List of files that are not downloaded. Wildcards are supported. Use it when you want to persist existing config files. Excludes takes precedence over includes.

.PARAMETER Includes
List of files to be copied. Wildcards are supported. Use it when you want to download only a subset from GitHub. Excludes takes precedence over includes.

.PARAMETER uAConfigArchive
Creates an uberAgent.uAConfig archive from the target directory. The uberAgent.uAConfig is placed in the root of the target folder.
The archive is downloaded by the endpoint agents and applied if meaningful changes are found. See https://uberagent.com/docs/uberagent/latest/advanced-topics/auto-application-of-configuration-changes/.
Default is true.

.PARAMETER ForceVersionUpdate
This updates the version setting in the uberAgent.conf so that the endpoint agent is forced to restart and update the config even if there were no meaningful changes.
Requires an existing uberAgent.conf in the target directory.
Default is false.

.PARAMETER RepoUrl
uberAgent GitHub repository URL. Typically there is no need to change this parameter.
Default is "https://github.com/vastlimits/uberAgent-config"

.EXAMPLE
.\InvokeuberAgentConfigDownload.ps1 -Branch "7.1" -TargetDirectory "\\server\share\uberAgentConfig" -Excludes "uberAgent.conf" -uAConfigArchive $true -ForceVersionUpdate $true
Download everything except uberAgent.conf. Create an uberAgent.uAConfig archive and update the version string to force the endpoint agent to apply the archive.

.EXAMPLE
.\InvokeuberAgentConfigDownload.ps1 -Branch "7.1" -TargetDirectory "\\server\share\uberAgentConfig" -Includes "uberAgent-ESA-am-*.conf", "uberAgent-ESA-si-*.conf", "Security inventory", "Security inventory\*"
Download only TDE rules and everything relevant to SCI tests

.EXAMPLE
.\InvokeuberAgentConfigDownload.ps1 -Branch "7.1" -TargetDirectory "\\server\share\uberAgentConfig" -Includes "uberAgent-ESA-am-*.conf", -Excludes "uberAgent-ESA-am-sigma-informational-*.conf"
Download all TDE rules except the informational ones from Sigma

.LINK
https://github.com/vastlimits/uberAgent-config
uberagent.com
#>

param (
    [string]$Branch,

    [Parameter(Mandatory=$true)]
    [string]$TargetDirectory,

    [string[]]$Excludes = @(),

    [string[]]$Includes = @(),

    [bool]$uAConfigArchive = $true,

    [bool]$ForceVersionUpdate = $false,

    [string]$RepoUrl = "https://github.com/vastlimits/uberAgent-config"
)

function Test-Pattern {
    param (
        [string]$inputString,
        [string[]]$patterns
    )

    foreach ($pattern in $patterns) {
        $wildcardPattern = New-Object System.Management.Automation.WildcardPattern $pattern
        if ($wildcardPattern.IsMatch($inputString)) {
            return $true
        }
    }
    return $false
}

function Test-GitInstallation {
    try {
        $gitVersion = & git --version
        if ($gitVersion -match "git version") {
            return $true
        }
    } catch {
        Write-Error "Git is not installed or not found in PATH."
        return $false
    }
}

function Invoke-GitClone {
    param (
        [string]$repoUrl,
        [string]$branch,
        [string[]]$exclude,
        [string[]]$include,
        [string]$targetDirectory,
        [bool]$uAConfigArchive,
        [bool]$forceVersionUpdate,
        [string]$date
    )

    # Create a temporary directory for the clone
    $tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null

    # Clone the latest snapshot from the chosen branch to the temp directory
    git clone -b $Branch $RepoUrl $tempDir --depth 1


    # Process the includes
    if ($include.Count -gt 0) {
        Get-ChildItem -Path $tempDir\config -Recurse | Where-Object { -not (Test-Pattern $_.FullName.Replace("$tempDir\config", '').Trim('\') $include) } | ForEach-Object {
            Remove-Item $_.FullName -Recurse -Force
        }
    }

    # Handle the excludes
    $items = Get-ChildItem -Path $tempDir -Recurse
    if ($items) {
        foreach ($item in $items) {
            if (Test-Pattern $item.FullName.Replace("$tempDir\config", '').Trim('\') $exclude) {
                Remove-Item -Path $item.FullName -Recurse -Force
            }
        }
    }

    # Copy files to the target directory
    Copy-Item -Path "$tempDir\config\*" -Destination $targetDirectory -Recurse -Force

    # Clean up temporary directory
    Remove-Item -Path $tempDir -Recurse -Force

    # Update the version string in the uberAgent.conf
    if ($forceVersionUpdate -eq $true) {
        $uberAgentDotConfPath = Join-Path $targetDirectory "uberAgent.conf"
        if (Test-Path $uberAgentDotConfPath) {

            # Read the file content
            $lines = Get-Content $uberAgentDotConfPath
            $inConfigurationBlock = $false
            $foundVersion = $false
            $newContent = @()

            foreach ($line in $lines) {
                # If we encounter the [Configuration_Settings platform=Windows||macOS] stanza header
                if ($line -match "^\s*\[Configuration_Settings.*\]\s*$") {
                    $inConfigurationBlock = $true

                    $newContent += $line

                    # Check the next lines for the Version key
                    for ($i = $newContent.Count; $i -lt $lines.Count; $i++) {
                        if ($lines[$i] -match "^\s*Version\s*=\s*.*") {
                            $foundVersion = $true
                            break
                        } elseif ($lines[$i] -match "^\s*\[.*\]\s*") {
                            break
                        }
                    }

                    # If Version key is not found, add it
                    if (-not $foundVersion) {
                        $newContent += "Version = $date"
                    }

                    continue
                }

                # If inside the [Configuration_Settings] block and the line matches the "Version =" pattern
                if ($inConfigurationBlock -and $line -match "^\s*Version\s*=\s*.*") {
                    $line = "Version = $date"
                    $foundVersion = $true
                }

                # If we find another stanza header
                if ($line -match "^\s*\[.*\]\s*") {
                    $inConfigurationBlock = $false
                }

                $newContent += $line
            }

            # Write the modified content back to the conf
            $newContent | Set-Content $uberAgentDotConfPath
        } else {
            Write-Warning "Version update desired but no uberAgent.conf was found in the target directory `"$targetDirectory`""
        }
    }

    # Create/update the uberAgent config archive
    if ($uAConfigArchive -eq $true) {
        $uAConfigArchiveFilePath = Join-Path -Path $targetDirectory -ChildPath "uberAgent.uAConfig"
        if (Test-Path $uAConfigArchiveFilePath) {
            Remove-Item $uAConfigArchiveFilePath -Force
        }

        $zipFilePath = Join-Path -Path $targetDirectory -ChildPath "config-temp.zip"
        Compress-Archive -Path "$targetDirectory\*" -DestinationPath $zipFilePath
        Move-Item $zipFilePath $uAConfigArchiveFilePath
    }



}

# Check for git installation
if (-not (Test-GitInstallation)) {
    exit
}

# Create a date variable to always work with the same date for all files
$date = Get-Date -Format 'yyyy-MM-dd-HH:mm:ss'

# Check the target folder
if (-not ($TargetDirectory -match "^\w:\\.*$|^\\\\.*$")) {
    Throw "Only full paths like C:\... or \\server\share are supported. Do not use relative paths."
}
if (-not (Test-Path $TargetDirectory)) {
    New-Item -Path $TargetDirectory -ItemType Directory -Force | Out-Null
}

# Call the function
Invoke-GitClone -branch $Branch -exclude $Excludes -include $Includes -targetDirectory $TargetDirectory -uAConfigArchive $uAConfigArchive -forceVersionUpdate $ForceVersionUpdate -repoUrl $RepoUrl -date $date
