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
      $riskScore = 100

      $SMBv1 = (Get-CimInstance -query "select * from  Win32_OptionalFeature where name = 'SMB1Protocol'").InstallState

      if ($SMBv1 -eq 2) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # SMBv1 is disabled
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      elseif ($SMBv1 -eq 1) {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # SMBv1 is enabled
         return New-vlResultObject -result $result -score 2 -riskScore $riskScore
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

   $riskScore = 40

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
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         elseif ($SMBSigningRequired -eq 0 -and $SMBSigningEnabled -eq 1) {
            $result = [PSCustomObject]@{
               state = "Enabled"
            }
            # SMB signing is enabled but not required
            return New-vlResultObject -result $result -score 2 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2 -riskScore $riskScore
         }
      }
      elseif ($SMBv1.Result -like '*false*') {
         $SMBSigningRequired = Get-vlRegValue -Hive "HKLM" -Path "System\CurrentControlSet\Services\LanManWorkstation\Parameters" -Value "RequireSecuritySignature"

         if ($SMBSigningRequired -eq 1) {
            $result = [PSCustomObject]@{
               state = "Required"
            }
            # SMB signing is required
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               state = "NotRequired"
            }
            # SMB signing is not required
            return New-vlResultObject -result $result -score 2 -riskScore $riskScore
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
      $riskScore = 20

      if ((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' | Where-Object -Property 'TcpipNetbiosOptions' -eq 1).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # NetBIOS is disabled
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # NetBIOS is enabled
         return New-vlResultObject -result $result -score 3 -riskScore $riskScore
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
      $riskScore = 20

      if (((Get-CimInstance -ClassName 'Win32_NetworkAdapterConfiguration' -Filter IPEnabled=TRUE | Where-Object -Property 'WINSPrimaryServer' -ne $null).ServiceName).Count -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # WINS is not in usage
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # WINS is in usage
         return New-vlResultObject -result $result -score 3 -riskScore $riskScore
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

   $riskScore = 40

   try {

      try {
         # 10240 = TLS 1.2 & TLS 1.3
         # 8192  = TLS 1.3
         # 2048  = TLS 1.2
         $DesiredValues = @(10240, 8192, 2048)

         $SecureProtocols = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Value SecureProtocols -IncludePolicies $true

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
         Description  = "This check is designed to verify the status of Server Message Block version 1 (SMBv1), a network protocol that provides shared access to files, printers, and serial ports within a network. SMBv1, while still functional, is an outdated version of the protocol and is known to have several security vulnerabilities. These vulnerabilities can potentially be exploited by malicious actors to gain unauthorized access to network resources or execute arbitrary code. Modern versions of the SMB protocol, such as SMBv2 and SMBv3, provide the same functionality but with improved performance and security."
         Score        = $SMBv1.Score
         ResultData   = $SMBv1.Result
         RiskScore    = $SMBv1.RiskScore
         ErrorCode    = $SMBv1.ErrorCode
         ErrorMessage = $SMBv1.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCSMBSign")) {
      $SMBSigning = Get-vlNetworkConfigurationSMBSigning
      $Output += [PSCustomObject]@{
         Name         = "NCSMBSign"
         DisplayName  = "Network Configuration SMB Signing"
         Description  = "This check is designed to confirm the configuration of Server Message Block (SMB) Signing, a security feature within the network protocol. SMB, used by Windows computers, facilitates shared access to files, printers, serial ports, and other resources on a network. However, without SMB Signing, these communications can be susceptible to man-in-the-middle attacks, where unauthorized individuals intercept and potentially alter the communication between the client and server."
         Score        = $SMBSigning.Score
         ResultData   = $SMBSigning.Result
         RiskScore    = $SMBSigning.RiskScore
         ErrorCode    = $SMBSigning.ErrorCode
         ErrorMessage = $SMBSigning.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCNetBIOS")) {
      $NetBIOS = Get-vlNetworkConfigurationNetBIOS
      $Output += [PSCustomObject]@{
         Name         = "NCNetBIOS"
         DisplayName  = "Network configuration NetBIOS"
         Description  = "This check is designed to ascertain the status of the Network Basic Input/Output System (NetBIOS), a software protocol that enables applications on different computers to communicate over a local area network (LAN). While NetBIOS can be beneficial for certain types of network communication, it's an older protocol that can pose security risks if left enabled. For instance, NetBIOS can potentially reveal sensitive system information to attackers on the same network, and it can also be exploited as a pathway for certain types of network attacks."
         Score        = $NetBIOS.Score
         ResultData   = $NetBIOS.Result
         RiskScore    = $NetBIOS.RiskScore
         ErrorCode    = $NetBIOS.ErrorCode
         ErrorMessage = $NetBIOS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("NCWINS")) {
      $WINS = Get-vlNetworkConfigurationWINS
      $Output += [PSCustomObject]@{
         Name         = "NCWINS"
         DisplayName  = "Network configuration WINS"
         Description  = "This check is designed to assess the configuration of Windows Internet Name Service (WINS), a legacy computer name registration and resolution service that maps network computer names to IP addresses. WINS, while functional, is an older system that has been largely superseded by more modern, secure, and efficient systems like DNS. WINS can pose potential security risks if left enabled and improperly configured. For instance, it can be exploited by attackers to redirect network traffic, gain unauthorized access to network resources, or execute arbitrary code."
         Score        = $WINS.Score
         ResultData   = $WINS.Result
         RiskScore    = $WINS.RiskScore
         ErrorCode    = $WINS.ErrorCode
         ErrorMessage = $WINS.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("MNCSSLTLS")) {
      $SSLTLS = Get-vlNetworkConfigurationSSLTLSLocalMachine
      $Output += [PSCustomObject]@{
         Name         = "MNCSSLTLS"
         DisplayName  = "Network configuration SSL/TLS - Machine"
         Description  = "This check is designed to verify that only newer versions of the Transport Layer Security (TLS) and Secure Sockets Layer (SSL) protocols are being used. TLS is the successor to SSL and is a cryptographic protocol that enables secure communications over a network. They are typically used to secure Internet traffic, email transmissions, and other types of network communications. The use of insecure or outdated versions of the protocols can pose significant security risks, including the exposure of sensitive data and vulnerability to various types of attacks, such as man-in-the-middle attacks. SSL and TLS, especially in their newer versions, provide robust security features that help protect data integrity and privacy."
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
