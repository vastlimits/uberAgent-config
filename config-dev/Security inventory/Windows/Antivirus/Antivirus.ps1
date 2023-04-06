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

   param (

   )

   process {
      try {
         $instances = Get-CimInstance -ClassName AntiVirusProduct -Namespace "root\SecurityCenter2"

         $riskScore = 100
         $score = 0
         $result = @()
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
                  $score = 4
               }
            }

            $result += [PSCustomObject]@{
               AntivirusEnabled  = $avEnabled
               AntivirusName     = $instance.displayName
               AntivirusUpToDate = $avUp2Date
            }
         }

         if (-not $avEnabledFound) {
            $score = 0
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
        Get-vlDefenderStatus
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

   <#
    if ($params.Contains("all") -or $params.Contains("AVDefStat")) {
        $defenderStatus = Get-vlDefenderStatus
        $Output += [PSCustomObject]@{
            Name       = "AVDefStat"
            DisplayName  = "Defender status"
            Description  = "Checks if the defender is enabled and up to date."
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
# SIG # Begin signature block
# MIIFowYJKoZIhvcNAQcCoIIFlDCCBZACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0XMi7SpXcwmANahTPQsazAjb
# ldOgggMsMIIDKDCCAhCgAwIBAgIQFf+KkCUt7J9Ay+NZ+dMpvjANBgkqhkiG9w0B
# AQsFADAsMSowKAYDVQQDDCFUZXN0IFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nIENl
# cnQwHhcNMjMwNDA2MDkwNDIzWhcNMjgwNDA2MDkxNDIzWjAsMSowKAYDVQQDDCFU
# ZXN0IFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nIENlcnQwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDGNh/YR7ouKwH6jZ90A3N+6hxgzWQQdoPchRC6CYYC
# iHL7KBDnY8ftWaq5Unre49YAQJzsNobxZi3S6xy+bdt2eBZyAaINYnLcgkoWlGeK
# OmCgoSxKH75Go55Tf1nhIw1mJZsafC6frv5M3EmVFI8frPSJK5X4w4z14qTsziz2
# gMxWvqaqgeIA+nMwvNGgN4e5seqLd00/RTMepNVwoBtnKFqXRPv1xocvfRQYB0Tr
# JIsFK3ztgBurNkaaaVM9jupH+53TI/7g7b0qVLIQ0qjLIaC8lpx5eE6mq2O66IpL
# SEBRTjad4idairpXuu8UtMQwbicIWn+tkDSjTeu5VlP5AgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUZkiDicEY
# 2vHryiFtS4lQTor6ci0wDQYJKoZIhvcNAQELBQADggEBAGLBwJy8i4BI/O63ID7h
# lrOdT3VOYPf29gFXZ4ldDLpY1/TJcPp53XTehWtO+Qztfy/nbCXWJsR8PR6djnTW
# 6lWQjXCP7N8DPiVU115Ha6D1mnyW9nGsOVeqd6doN9swXbSJ8VIi9Okv6IlDGYPS
# SvcbvnEz4BT1NmtMaY8ensTQm2FvAcjvFq09n89xoeJ0ifQ2t5NNhdRN1fY1J6OL
# NHyrmKGQ3dTJZDbiuQ9QNXx/G7J9ieZkduTh73wQRkCBM22Al4QzyMnbRg7wY4/X
# tzszEv4eV3Bg+RXMlTsCOP59AO2rCh02w/iSPQk/l3siVXT1bVW4tNvS15eWbcOk
# jDYxggHhMIIB3QIBATBAMCwxKjAoBgNVBAMMIVRlc3QgUG93ZXJTaGVsbCBDb2Rl
# IFNpZ25pbmcgQ2VydAIQFf+KkCUt7J9Ay+NZ+dMpvjAJBgUrDgMCGgUAoHgwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU
# mS3tQELvoEWwAxZtaQ6RbRXCJ7owDQYJKoZIhvcNAQEBBQAEggEAdIiZAMA0xQvr
# +tXFcRYaJ00SRWFbGLzCMOXLzj2zAmnKuAVFu4oxWFYyG1+KFkfudcicXz0rLW0Z
# dGfPSc+n81Sbh2TsTYJVmMZ93/qOGSvX1NR26YfDcE1eWQA4iK1fD+SJoQto/1kS
# umTvbyeRJNiJ8ArtbjR2OTxIHJ8ZyC5hm8xa6QShDNxOclth4d2Xje6i0rFIdLwN
# ei1GepCT8AA9hDBA+eC4Fh+cv9vfAQb+YvxVhTg07fV1ND+IfYL4ieU8fTITZFly
# 4NhwxGw2uzjWry4ZdfDdmUQvI7NUjQlyjPQl6+exgF9kDlajSxsbiXwruPlcvjw7
# Jw4CHxGiow==
# SIG # End signature block
