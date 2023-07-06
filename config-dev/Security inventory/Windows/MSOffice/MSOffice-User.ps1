#Requires -RunAsAdministrator
#Requires -Version 3.0

. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlGetLatestOfficeVersion {
   <#
    .SYNOPSIS
         Get the version of the installed MS Office
    .DESCRIPTION
         Get the version of the installed MS Office
    .OUTPUTS
         A [psobject] containing the version of the installed MS Office
    .EXAMPLE
        Get-vlGetLatestOfficeVersion
    #>

   process {
      try {
         #$versionList = @()
         $OfficeVersions = @("16.0", "15.0", "14.0", "12.0")
         $OfficeSubKeys = Get-vlRegSubkeys -Hive "HKCU" -Path "\Software\Microsoft\Office"

         foreach ($version in $OfficeVersions) {
            if ($OfficeSubKeys.PSChildName -contains $version) {
               return $version
            }
         }

         return $null
      }
      catch {
         return New-vlErrorObject($_)
      }
   }
}

function Get-vlMacroConfig {
   <#
    .SYNOPSIS
         Gets the macro configuration for the installed MS Office products
    .DESCRIPTION
         Gets the macro configuration for the installed MS Office productse
    .OUTPUTS
         A [psobject] containing the macro configuration for the installed MS Office products
    .EXAMPLE
        Get-vlMacroConfig
    #>

   $results = @{}
   $version = Get-vlGetLatestOfficeVersion
   $OfficeApplications = "Word", "Excel", "PowerPoint", "Outlook", "MS Project", "Visio", "Access", "Publisher"
   <#
      // 4 = Disabled without notification
      // 3 = Only digitally signed
      // 2 = Disabled with notification
      // 1 = Enable all macros
   #>
   foreach ($application in $OfficeApplications) {
      $RegPath = "software\microsoft\office\{0}\{1}\security" -f $version, $application
      if ($application -eq "Outlook") {
         $setting = Get-vlRegValue -Hive "HKCU" -Path $RegPath -Value "vbawarnings" -IncludePolicies $true

         if ($null -eq $setting) {
            $setting = Get-vlRegValue -Hive "HKCU" -Path $RegPath -Value "Level" -IncludePolicies $true
         }
      }
      else {
         $setting = Get-vlRegValue -Hive "HKCU" -Path $RegPath -Value "vbawarnings" -IncludePolicies $true
      }
      # check if setting is not null if it is null set it to 0
      if ($null -eq $setting) {
         $setting = 0
      }

      $results[$application] = $setting
   }
   return $results
}

function Get-vlIsVBADisabled {
   <#
    .SYNOPSIS
         Check if VBA is disabled for the installed MS Office products
    .DESCRIPTION
         Check if VBA is disabled for the installed MS Office products
    .OUTPUTS
         A [psobject] Disabled = true if VBA is disabled
    .EXAMPLE
        Get-vlIsVBADisabled
    #>

   process {
      $riskScore = 70

      try {
         $latestVersion = Get-vlGetLatestOfficeVersion
         #$macroConfig = Get-vlMacroConfig

         if ($null -ne $latestVersion) {
            # office is installed
            $vbaState = Get-vlRegValue -Hive "HKCU" -Path "\Software\Microsoft\Office\$latestVersion\Common" -Value "vbaoff" -IncludePolicies $true

            if ($vbaState -eq 1) {
               $result = [PSCustomObject]@{
                  Disabled = $true
               }

               return New-vlResultObject -Score 10 -Result $result -riskScore $riskScore
            }
            else {
               $result = [PSCustomObject]@{
                  Disabled = $false
               }

               return New-vlResultObject -Score 3 -Result $result -riskScore $riskScore
            }
         }
      }
      catch {
         return New-vlErrorObject($_)
      }
   }
}

function Get-vlMSOfficeCheck {
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

   if ($params.Contains("all") -or $params.Contains("MSOCUVBA")) {
      $vbaDisabled = Get-vlIsVBADisabled
      $Output += [PSCustomObject]@{
         Name         = "MSOCUVBA"
         DisplayName  = "MS Office VBA disabled"
         Description  = "This check is used to examine the status of Visual Basic for Applications (VBA) in Microsoft Office. VBA is a programming language used to automate tasks in Microsoft Office applications. While it can be a powerful tool for productivity, it can also be a security risk if misused, as it can be used to create macros that perform malicious actions."
         Score        = $vbaDisabled.Score
         ResultData   = $vbaDisabled.Result
         RiskScore    = $vbaDisabled.RiskScore
         ErrorCode    = $vbaDisabled.ErrorCode
         ErrorMessage = $vbaDisabled.ErrorMessage
      }
   }

   Write-Output $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlMSOfficeCheck | ConvertTo-Json -Compress)
