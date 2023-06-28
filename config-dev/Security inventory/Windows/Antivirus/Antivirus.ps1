#Requires -RunAsAdministrator
#Requires -Version 3.0

. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#https://mcpforlife.com/2020/04/14/how-to-resolve-this-state-value-of-av-providers/
[Flags()] enum ProductState {
   Off = 0x0000
   On = 0x1000
   Snoozed = 0x2000
   Expired = 0x3000
}

[Flags()] enum SignatureStatus {
   UpToDate = 0x00
   OutOfDate = 0x10
}

[Flags()] enum ProductOwner {
   NonMs = 0x000
   Windows = 0x100
}

[Flags()] enum ProductFlags {
   SignatureStatus = 0x000000F0
   ProductOwner = 0x00000F00
   ProductState = 0x0000F000
}

function Get-vlAntivirusStatus {
   <#
    .SYNOPSIS
        Get the status of the antivirus software
    .DESCRIPTION
        Get the status of the antivirus software
        This cmdlet is only available on the Windows platform.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the status of the antivirus software
    .EXAMPLE
        Get-vlAntivirusStatus
    #>

   process {
      try {
         $result = @()
         $score = 0
         $riskScore = 100

         $instances = Get-MpComputerStatus

         $defenderStatus = [PSCustomObject]@{
            AMEngineVersion                 = if ($instances.AMEngineVersion) { $instances.AMEngineVersion } else { "" }
            AMServiceEnabled                = if ($instances.AMServiceEnabled) { $instances.AMServiceEnabled } else { "" }
            AMServiceVersion                = if ($instances.AMServiceVersion) { $instances.AMServiceVersion } else { "" }
            AntispywareEnabled              = if ($instances.AntispywareEnabled) { $instances.AntispywareEnabled } else { "" }
            AntivirusEnabled                = if ($instances.AntivirusEnabled) { $instances.AntivirusEnabled } else { "" }
            AntispywareSignatureLastUpdated = if ($instances.AntispywareSignatureLastUpdated) { $instances.AntispywareSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ss") } else { "" }
            AntispywareSignatureVersion     = if ($instances.AntispywareSignatureVersion) { $instances.AntispywareSignatureVersion } else { "" }
            AntivirusSignatureLastUpdated   = if ($instances.AntivirusSignatureLastUpdated) { $instances.AntivirusSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ss") } else { "" }
            QuickScanSignatureVersion       = if ($instances.QuickScanSignatureVersion) { $instances.QuickScanSignatureVersion } else { "" }
         }

         $isWindowsServer = Get-vlIsWindowsServer

         if ($isWindowsServer -eq $false) {
            $instances = Get-CimInstance -ClassName AntiVirusProduct -Namespace "root\SecurityCenter2"
            $avEnabledFound = $false

            foreach ($instance in $instances) {
               $avEnabled = $([ProductState]::On.value__ -eq $($instance.productState -band [ProductFlags]::ProductState) )
               $avUp2Date = $([SignatureStatus]::UpToDate.value__ -eq $($instance.productState -band [ProductFlags]::SignatureStatus) )

               if ($avEnabled) {
                  $avEnabledFound = $true
                  if ($avUp2Date) {
                     $score = 10
                  }
                  else {
                     $score = 5
                  }
               }

               if ($instance.displayName -eq "Windows Defender" -or "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}" -eq $instance.instanceGuid) {

                  if ($avEnabled -eq $false) {
                     $result += [PSCustomObject]@{
                        Enabled  = $avEnabled
                        Name     = $instance.displayName
                        UpToDate = $avUp2Date
                     }
                  }
                  else {
                     $result += [PSCustomObject]@{
                        Enabled  = $avEnabled
                        Name     = $instance.displayName
                        UpToDate = $avUp2Date
                        Defender = $defenderStatus
                     }

                     $score -= Get-vlTimeScore($defenderStatus.AntispywareSignatureLastUpdated)
                     $score -= Get-vlTimeScore($defenderStatus.AntivirusSignatureLastUpdated)
                  }
               }
               else {
                  $result += [PSCustomObject]@{
                     Enabled  = $avEnabled
                     Name     = $instance.displayName
                     UpToDate = $avUp2Date
                  }
               }
            }

            if (-not $avEnabledFound) {
               $score = 0
            }
         }
         else {
            $result = @()
            $score = 0

            if ($defenderStatus -and $defenderStatus.AMServiceEnabled -and $defenderStatus.AntispywareEnabled -and $defenderStatus.AntivirusEnabled) {
               $score = 10

               $score -= Get-vlTimeScore($defenderStatus.AntispywareSignatureLastUpdated)
               $score -= Get-vlTimeScore($defenderStatus.AntivirusSignatureLastUpdated)

               $result += [PSCustomObject]@{
                  Enabled  = $true
                  Name     = "Windows Defender"
                  UpToDate = if ($score -eq 10) { $true } else { $false }
                  Defender = $defenderStatus
               }
            }
            elseif ($defenderStatus) {
               $result += [PSCustomObject]@{
                  Enabled  = $false
                  Name     = "Windows Defender"
                  UpToDate = if ($score -eq 10) { $true } else { $false }
                  Defender = $defenderStatus
               }
            }
            else {
               return New-vlErrorObject -message "Status could not be determined because SecurityCenter2 is not available on Windows Server." -errorCode 1 -context $_
            }
         }
         
         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
      catch {
         return New-vlErrorObject($_)
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

   if ($params.Contains("all") -or $params.Contains("AVState")) {
      $avStatus = Get-vlAntivirusStatus
      $Output += [PSCustomObject]@{
         Name         = "AVState"
         DisplayName  = "Antivirus status"
         Description  = "Checks if the antivirus is enabled and up to date."
         Score        = $avStatus.Score
         ResultData   = $avStatus.Result
         RiskScore    = $avStatus.RiskScore
         ErrorCode    = $avStatus.ErrorCode
         ErrorMessage = $avStatus.ErrorMessage
      }
   }

   Write-Output $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlAntivirusCheck | ConvertTo-Json -Compress)
