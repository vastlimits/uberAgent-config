#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlNetworkConfigurationSSLTLSUser {
   <#
   .SYNOPSIS
       Checks whether only secure protocols are used
   .DESCRIPTION
      Checks whether only secure protocols are used
   .OUTPUTS
       If only secure protocols are used, the function returns a PSCustomObject with the following properties:
       SecureProtocolsOnly: true
       If not only secure protocols are used, the function returns a PSCustomObject with the following properties:
       SecureProtocolsOnly: false
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationSSLTLSUser
   #>

   try {
      $riskScore = 40

      # 10240 = TLS 1.2 & TLS 1.3
      # 8192  = TLS 1.3
      # 2048  = TLS 1.2
      $DesiredValues = @(10240,8192,2048)

      $SecureProtocols = Get-vlRegValue -Hive "HKCU" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Value SecureProtocols -IncludePolicies $true

      if ($DesiredValues -contains $SecureProtocols) {
         $result = [PSCustomObject]@{
            SecureProtocolsOnly = $true
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            SecureProtocolsOnly = $false
         }

         return New-vlResultObject -result $result -score 4 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}


function Get-vlNetworkConfigurationCheck {
   <#
   .SYNOPSIS
       Function that performs the network configuration check and returns the result to the uberAgent.
   .DESCRIPTION
       Function that performs the network configuration check and returns the result to the uberAgent.
   .NOTES
       The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
       Specific tests can be called by passing the test name as a parameter to the script args.
       Passing no parameters or -all to the script will run all tests.
   .LINK
       https://uberagent.com
   .OUTPUTS
       A list with vlResultObject | vlErrorObject [psobject] containing the test results
   .EXAMPLE
       Get-vlNetworkConfigurationCheck
   #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("UNCSSLTLS")) {
      $SSLTLS = Get-vlNetworkConfigurationSSLTLSUser
      $Output += [PSCustomObject]@{
         Name         = "UNCSSLTLS"
         DisplayName  = "Network configuration SSL/TLS - User"
         Description  = "Checks whether only secure protocols are used"
         Score        = $SSLTLS.Score
         ResultData   = $SSLTLS.Result
         RiskScore    = $SSLTLS.RiskScore
         ErrorCode    = $SSLTLS.ErrorCode
         ErrorMessage = $SSLTLS.ErrorMessage
      }
   }


   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-vlNetworkConfigurationCheck | ConvertTo-Json -Compress)
