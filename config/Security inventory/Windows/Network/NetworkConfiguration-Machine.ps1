#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlNetworkConfigurationSMBv1 {
   <#
   .SYNOPSIS
       Checks whether SMBv1 is enabled
   .DESCRIPTION
       Checks whether SMBv1 is enabled
   .OUTPUTS
       If SMBv1 is enabled, the function returns a PSCustomObject with the following properties:
       enabled: true
       If SMBv1 is disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES
       Ref: https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=client
   .EXAMPLE
       Get-vlNetworkConfigurationSMBv1
   #>

   try {

      $SMBv1 = (Get-CimInstance -query "select * from  Win32_OptionalFeature where name = 'SMB1Protocol'").InstallState

      if ($SMBv1 -eq 2) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # SMBv1 is disabled
         return New-vlResultObject -result $result -score 10
      }
      elseif ($SMBv1 -eq 1) {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # SMBv1 is enabled
         return New-vlResultObject -result $result -score 2
      }
      else {
         return New-vlErrorObject("SMBv1 install state must be 1 or 2 but is $SMBv1")
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationSMBSigning {
   <#
   .SYNOPSIS
       Checks whether SMB signing enabled
   .DESCRIPTION
       Checks whether SMB signing enabled
   .OUTPUTS
       If SMB signing is enabled, the function returns a PSCustomObject with the following properties:
       enabled: true
       If SMB signing is disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES
       Ref: https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102
   .EXAMPLE
       Get-vlNetworkConfigurationSMBSigning
   #>

   try {
      $SMBv1 = Get-vlNetworkConfigurationSMBv1

      if ($SMBv1.Result -like '*true*') {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"
         $SMBSigningEnabled = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "EnableSecuritySignature"

         if ($SMBSigningRequired -eq 1) {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10
         }
         elseif ($SMBSigningRequired -eq 0 -and $SMBSigningEnabled -eq 1) {
            $result = [PSCustomObject]@{
               state = "Enabled"
            }
            # SMB signing is enabled but not required
            return New-vlResultObject -result $result -score 2
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2
         }
      }
      elseif ($SMBv1.Result -like '*false*') {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"

         if ($SMBSigningRequired -eq 1) {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2
         }

      }
      else {
         Throw "Return of Get-vlNetworkConfigurationSMBv1 is invalid"
         return New-vlErrorObject($Error)
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationNetBIOS {
   <#
   .SYNOPSIS
       Checks whether NetBIOS is enabled
   .DESCRIPTION
       Checks whether NetBIOS is enabled
   .OUTPUTS
       If NetBIOS is enabled, the function returns a PSCustomObject with the following properties:
       enabled: true
       If NetBIOS is disabled, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationNetBIOS
   #>

   try {
      if ((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object -Property 'TcpipNetbiosOptions' -eq 1).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # NetBIOS is disabled
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # NetBIOS is enabled
         return New-vlResultObject -result $result -score 3
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationWINS {
   <#
   .SYNOPSIS
       Checks whether WINS is used
   .DESCRIPTION
       Checks whether WINS is used
   .OUTPUTS
       If WINS is used, the function returns a PSCustomObject with the following properties:
       enabled: true
       If WINS is used, the function returns a PSCustomObject with the following properties:
       enabled: false
   .NOTES

   .EXAMPLE
       Get-vlNetworkConfigurationWINS
   #>

   try {
      if (((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter IPEnabled=TRUE | Where-Object -Property 'WINSPrimaryServer' -ne $null).ServiceName).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # WINS is not in usage
         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # WINS is in usage
         return New-vlResultObject -result $result -score 3
      }
   }
   catch {
      return New-vlErrorObject($_)
   }
}

function Get-vlNetworkConfigurationSSLTLSLocalMachine {
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
       Get-vlNetworkConfigurationSSLTLSLocalMachine
   #>

   try {

      try {

         $DesiredValue = 2560 # Use TLS 1.1 and TLS 1.2

         $SecureProtocols = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Value SecureProtocols -IncludePolicies $true

         if ($SecureProtocols -eq $DesiredValue) {
            $result = [PSCustomObject]@{
               SecureProtocolsOnly = $true
            }

            return New-vlResultObject -result $result -score 10
         }
         else {
            $result = [PSCustomObject]@{
               SecureProtocolsOnly = $false
            }

            return New-vlResultObject -result $result -score 4
         }
      }
      catch {
         return New-vlErrorObject($_)
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

   if ($params.Contains("all") -or $params.Contains("NCSMBv1")) {
      $SMBv1 = Get-vlNetworkConfigurationSMBv1
      $Output += [PSCustomObject]@{
         Name         = "NCSMBv1"
         DisplayName  = "Network Configuration SMBv1"
         Description  = "Checks whether SMBv1 is enabled."
         Score        = $SMBv1.Score
         ResultData   = $SMBv1.Result
         RiskScore    = 100
         ErrorCode    = $SMBv1.ErrorCode
         ErrorMessage = $SMBv1.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCSMBSign")) {
      $SMBSigning = Get-vlNetworkConfigurationSMBSigning
      $Output += [PSCustomObject]@{
         Name         = "NCSMBSign"
         DisplayName  = "Network Configuration SMB Signing"
         Description  = "Checks whether SMB signing is enabled."
         Score        = $SMBSigning.Score
         ResultData   = $SMBSigning.Result
         RiskScore    = 40
         ErrorCode    = $SMBSigning.ErrorCode
         ErrorMessage = $SMBSigning.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCNetBIOS")) {
      $NetBIOS = Get-vlNetworkConfigurationNetBIOS
      $Output += [PSCustomObject]@{
         Name         = "NCNetBIOS"
         DisplayName  = "Network configuration NetBIOS"
         Description  = "Checks whether NetBIOS is enabled."
         Score        = $NetBIOS.Score
         ResultData   = $NetBIOS.Result
         RiskScore    = 20
         ErrorCode    = $NetBIOS.ErrorCode
         ErrorMessage = $NetBIOS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCWINS")) {
      $WINS = Get-vlNetworkConfigurationWINS
      $Output += [PSCustomObject]@{
         Name         = "NCWINS"
         DisplayName  = "Network configuration WINS"
         Description  = "Checks whether WINS is enabled."
         Score        = $WINS.Score
         ResultData   = $WINS.Result
         RiskScore    = 20
         ErrorCode    = $WINS.ErrorCode
         ErrorMessage = $WINS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("MNCSSLTLS")) {
      $SSLTLS = Get-vlNetworkConfigurationSSLTLSLocalMachine
      $Output += [PSCustomObject]@{
         Name         = "MNCSSLTLS"
         DisplayName  = "Network configuration SSL/TLS - Machine"
         Description  = "Checks whether only secure protocols are used"
         Score        = $SSLTLS.Score
         ResultData   = $SSLTLS.Result
         RiskScore    = 40
         ErrorCode    = $SSLTLS.ErrorCode
         ErrorMessage = $SSLTLS.ErrorMessage
      }
   }


   return $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Output (Get-vlNetworkConfigurationCheck | ConvertTo-Json -Compress)
