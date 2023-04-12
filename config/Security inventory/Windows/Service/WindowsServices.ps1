. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlServiceLocations {
   <#
   .SYNOPSIS
       Checks whether services are located outside common locations
   .DESCRIPTION
       Checks whether services are located outside common locations
   .LINK

   .NOTES

   .OUTPUTS
       A [psobject] containing services located outside common locations. Empty if nothing was found.
   .EXAMPLE
       Get-vlServiceLocations
   #>

   param (

   )

   process {
      try {
         $ServiceArray = @()
         Get-vlRegSubkeys -Hive HKLM -Path 'SYSTEM\CurrentControlSet\Services' | Where-Object { $_.ImagePath } | ForEach-Object -process {
            $ImagePath = $PSItem.ImagePath
            if ($ImagePath -inotmatch '^(\\\?\?\\)?\\?SystemRoot.*$|^(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\WINDOWS\\(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\Program Files( \(x86\))?\\.*$|^(\\\?\?\\)?"?C:\\WINDOWS\\Microsoft\.NET\\.*$|^(\\\?\?\\)?"?C:\\ProgramData\\Microsoft\\Windows Defender\\.*$') {
               $ServiceArray += $ImagePath
            }

         }

         if ($ServiceArray.Count -eq 0) {
            $result = [PSCustomObject]@{
               Services = ""
            }
            # No services outside common locations found
            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               Services = $ServiceArray
            }
            # Services outside common location found
            return New-vlResultObject -result $result -score 1
         }
      }
      catch {

         return New-vlErrorObject($_)
      }
      finally {

      }

   }

}

function Get-vlServiceDLLLocations {
   <#
    .SYNOPSIS
        Checks whether service.dll files are located outside common locations
    .DESCRIPTION
        Checks whether service.dll files are located outside common locations
    .LINK

    .NOTES

    .OUTPUTS
        A [psobject] containing services with service.dll files located outside common locations. Empty if nothing was found.
    .EXAMPLE
        Get-vlServiceDLLLocations
    #>

   param (

   )

   process {
      try {
         $ServiceArray = @()
         $ServiceDLLArray = @()
         Get-ItemProperty hklm:\SYSTEM\CurrentControlSet\Services\*\Parameters | Where-Object { $_.servicedll } | ForEach-Object -process {

            $ServiceDLL = $PSItem.ServiceDLL
            $ServiceName = ($PSItem.PSParentPath).split('\\')[-1]
            if ($ServiceDLL -inotmatch '^C:\\WINDOWS\\system32.*$') {

               $ServiceArray += $ServiceName
               $ServiceDLLArray += $ServiceDLL
            }

         }

         if ($ServiceArray.Count -eq 0) {
            $result = [PSCustomObject]@{
               Services    = ""
               ServiceDLLs = ""
            }
            # No service.dll file outside common locations found
            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               Services    = $ServiceArray
               ServiceDLLs = $ServiceDLLArray
            }
            # Service.dll file outside common location found
            return New-vlResultObject -result $result -score 1
         }
      }
      catch {

         return New-vlErrorObject($_)
      }
      finally {

      }

   }

}


function Get-vlWindowsServicesCheck {
   <#
   .SYNOPSIS
       Function that performs the Windows services check and returns the result to the uberAgent.
   .DESCRIPTION
       Function that performs the Windows services check and returns the result to the uberAgent.
   .NOTES
       The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
       Specific tests can be called by passing the test name as a parameter to the script args.
       Passing no parameters or -all to the script will run all tests.
   .LINK
       https://uberagent.com
   .OUTPUTS
       A list with vlResultObject | vlErrorObject [psobject] containing the test results
   .EXAMPLE
       Get-vlWindowsServicesCheck
   #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("ServiceLocations")) {
      $ServiceLocations = Get-vlServiceLocations
      $Output += [PSCustomObject]@{
         Name         = "Locations"
         DisplayName  = "Uncommon locations"
         Description  = "Checks whether services are running in uncommon locations"
         Score        = $ServiceLocations.Score
         ResultData   = $ServiceLocations.Result
         RiskScore    = 100
         ErrorCode    = $ServiceLocations.ErrorCode
         ErrorMessage = $ServiceLocations.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("ServiceDLLLocations")) {
      $ServiceDLLLocations = Get-vlServiceDLLLocations
      $Output += [PSCustomObject]@{
         Name         = "Service.dll"
         DisplayName  = "Uncommon locations of service.dll"
         Description  = "Checks whether services use service.dll in uncommon locations"
         Score        = $ServiceDLLLocations.Score
         ResultData   = $ServiceDLLLocations.Result
         RiskScore    = 90
         ErrorCode    = $ServiceDLLLocations.ErrorCode
         ErrorMessage = $ServiceDLLLocations.ErrorMessage
      }
   }

   return $output
}

Write-Output (Get-vlWindowsServicesCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIFowYJKoZIhvcNAQcCoIIFlDCCBZACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAXVB9RMuFOSd3gjpd3GHcyYG
# 266gggMsMIIDKDCCAhCgAwIBAgIQFf+KkCUt7J9Ay+NZ+dMpvjANBgkqhkiG9w0B
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
# XGKlaHjU4naTpj9BF0iEcGVT2ogwDQYJKoZIhvcNAQEBBQAEggEAVdVpUfSbAXXF
# LnKZDxvE7o4q5pPTxPVRzIzH3nW3LViBzdFT9AMk2jo5ZrlMDLOuDs6BPTnNiyht
# VZecY27FFI9HVllRhQhMRPaR8oGrlLatwXRpniTcseQgv7TjT9+aC+KEHFL67mTV
# d9AHA0p9dmaH084Zn6wQHhPh920uQTfS75BegFKPQWJnLVbez5dhg/BIoLlbDfyx
# ofwl4A+cHoe0lJ+IOd6mwSkbpcPc4gimB0VrPdziG5UpOl7819QUINR8eiS9DzrK
# 6FkArdT68cDcLkht4kSEn6D6p/acwbKwnY8GmN+TOSFpyANti+Cg2Q+94PlJEYCx
# JDEETsOU2w==
# SIG # End signature block
