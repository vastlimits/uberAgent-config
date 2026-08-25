#Requires -RunAsAdministrator
#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlPowerShellV2Status {
   <#
    .SYNOPSIS
        Performs a check if PowerShell V2 is installed on the system
    .DESCRIPTION
        Performs a check if PowerShell V2 is installed on the system
    .NOTES
        This function requires elevated privilegs
        https://devblogs.microsoft.com/powershell/windows-powershell-2-0-deprecation/
    .OUTPUTS
        A [psobject] containing the status of the PowerShell V2 installation
    .EXAMPLE
        Get-vlPowerShellV2Status
    #>

   process {
      $riskScore = 60

      try {
         $currentPowerShellVersion = $PSVersionTable.PSVersion.ToString()
         $powerShellV2Enabled = $null

         #check if PowerShell V2 is installed on the system
         try {
            $installationStatus = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop

            if ($installationStatus.State -eq "Enabled") {
               $powerShellV2Enabled = $true
            }
            else {
               $powerShellV2Enabled = $false
            }
         }
         catch {
            # check if HKEY_LOCAL_MACHINE\Software\Microsoft\PowerShell\1\PowerShellEngine exists
            $powerShellV2Enabled = Test-Path -Path "HKLM:\Software\Microsoft\PowerShell\1\PowerShellEngine" -ErrorAction Stop
         }

         $result = [PSCustomObject]@{
            PowerShellV2Enabled = $powerShellV2Enabled
            DefaultVersion      = $currentPowerShellVersion
         }

         if ($result.PowerShellV2Enabled) {
            return New-vlResultObject -result $result -score 4 -riskScore $riskScore
         }
         else {
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
      }
      catch {
         return New-vlErrorObject -context $_
      }
   }
}

function Get-vlPowerShellCL {
   <#
    .SYNOPSIS
        Checks the current PowerShell LanguageMode
    .DESCRIPTION
        Checks the current PowerShellLanguageMode
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell LanguageMode
    .NOTES
        https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.3
    .EXAMPLE
        Get-vlPowerShellCL
    #>

   process {
      try {
         $score = 7
         $riskScore = 30

         $result = [PSCustomObject]@{
            LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
      catch {

         return New-vlErrorObject -context $_
      }
   }

}

Function Get-vlPowerShellRemotingStatus {
   <#
    .SYNOPSIS
        Checks the current PowerShell remoting status
    .DESCRIPTION
        Checks the current PowerShell remoting status
    .LINK
        https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.3
    .OUTPUTS
        A [psobject] containing the current PowerShell remoting status
    .EXAMPLE
        Get-vlPowerShellRemotingStatus
    #>

   try {
      $serviceStatus = Get-Service -Name WinRM -ErrorAction Stop | Select-Object -ExpandProperty Status

      #if the service is not running, remoting is disabled
      if ($serviceStatus -ne "Running") {
         $result = [PSCustomObject]@{
            RemotingEnabled = $false
            JEAEnabled      = $false
         }

         return New-vlResultObject -result $result -score 10 -riskScore 50
      }

      $remotingEnabled = $null

      # Try to open a session to localhost
      try {
         $session = New-PSSession -ComputerName localhost -ErrorAction Stop

         # Close the session
         Remove-PSSession $session -ErrorAction Stop
         $remotingEnabled = $true
      }
      catch {
         $remotingEnabled = $false
      }

      # Check if JEA is enabled
      $JEAState = Get-vlJEACheck

      # If the session is opened, remoting is enabled
      $result = [PSCustomObject]@{
         RemotingEnabled = $remotingEnabled
         JEAEnabled      = $JEAState
      }

      if ($JEAState) {
         return New-vlResultObject -result $result -score 8 -riskScore 30
      }
      else {
         return New-vlResultObject -result $result -score 4 -riskScore 50
      }
   }
   catch {
      $result = [PSCustomObject]@{
         RemotingEnabled = $false
         JEAEnabled      = $false
      }
      # If the session cannot be opened, remoting is disabled
      return New-vlResultObject -result $result -score 10 -riskScore 30
   }
}

function Get-vlPowerShellExecutionPolicy {
   <#
    .SYNOPSIS
        Checks the current PowerShell execution policy for the current user
    .DESCRIPTION
        Checks the current PowerShell execution policy for the current user
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell execution policy
    .EXAMPLE
        Get-vlPowerShellExecutionPolicy
    #>

   param ()

   process {
      try {
         $result = [PSCustomObject]@{
            ExecutionPolicy = "Undefined"
         }

         $policys = Get-ExecutionPolicy -List -ErrorAction Stop

         # go from lowest to highest
         # first check LocalMachine policy
         $policy = $policys | Where-Object Scope -eq "LocalMachine"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         # check CurrentUser policy
         $policy = $policys | Where-Object Scope -eq "CurrentUser"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         # check UserPolicy policy
         $policy = $policys | Where-Object Scope -eq "UserPolicy"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         # check MachinePolicy policy
         $policy = $policys | Where-Object Scope -eq "MachinePolicy"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         $LMrisk = 70
         $LMLevel = 2

         # Level 0: Unrestricted
         # Level 1: Bypass
         # Level 2: RemoteSigned
         # Level 3: AllSigned
         # Level 4: Restricted
         # Level 5: Undefined

         switch ($result.ExecutionPolicy) {
            "Unrestricted" {
               $LMLevel = 2
            }
            "Bypass" {
               $LMLevel = 2
            }
            "RemoteSigned" {
               $LMLevel = 6
            }
            "AllSigned" {
               $LMLevel = 8
            }
            "Restricted" {
               $LMLevel = 10
            }
            "Undefined" {
               $LMLevel = 10
            }
         }

         if ($result.ExecutionPolicy -ne "Undefined") {
            return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
         }

         $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
         <#
                Work Station (1)
                Domain Controller (2)
                Server (3)
            #>

         # If the execution policy in all scopes is Undefined, the effective execution policy is Restricted for Windows clients and RemoteSigned for Windows Server.
         if ($osInfo.ProductType -eq 1) {
            return New-vlResultObject -result $result -score 10 -riskScore $LMrisk
         }
         else {
            return New-vlResultObject -result $result -score 6 -riskScore $LMrisk
         }
      }
      catch {

         return New-vlErrorObject -context $_
      }
      finally {

      }
   }

}

Function Get-vlPowerShellLoggingTranscriptionStatus {
   <#
    .SYNOPSIS
        Checks the current transcription logging status
    .DESCRIPTION
        Checks the current transcription logging status by checking the registry and group policy
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current transcription logging status
    .EXAMPLE
        Get-vlPowerShellLoggingTranscriptionStatus
    #>

   $result = $false

   try {
      $transcription = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\PowerShell\Transcription" -Value "EnableTranscripting" -IncludePolicies $true
      if ( $transcription -eq 1) {
         $result = $true
      }
   }
   catch {
      return $result
   }

   return $result
}

Function Get-vlPowerShellLoggingScriptBlockStatus {
   <#
    .SYNOPSIS
        Checks the current script block logging status
    .DESCRIPTION
        Checks the current script block logging status by checking the registry and group policy
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current script block logging status
    .EXAMPLE
        Get-vlPowerShellLoggingScriptBlockStatus
    #>


   $result = $false

   try {
      $scriptBlockLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Value "EnableScriptBlockLogging" -IncludePolicies $true
      if ($scriptBlockLogging -eq 1) {
         $result = $true
      }
   }
   catch {
      return $result
   }

   return $result
}

Function Get-vlPowerShellLoggingModuleLogging {
   <#
    .SYNOPSIS
        Checks the current script module logging status
    .DESCRIPTION
        Checks the current script module logging status by checking the registry and group policy
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current script block logging status
    .EXAMPLE
        Get-vlPowerShellLoggingModuleLogging
    #>

   $result = $false

   try {
      $enableModuleLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\PowerShell\ModuleLogging" -Value "EnableModuleLogging" -IncludePolicies $true
      if ($enableModuleLogging -eq 1) {
         $result = $true
      }
   }
   catch {
      return $result
   }

   return $result
}

function Get-vlPowerShellLogging {
   <#
    .SYNOPSIS
        Checks the current PowerShell logging settings
    .DESCRIPTION
        Checks the current PowerShell logging settings by reading the registry
    .LINK
        https://adamtheautomator.com/powershell-logging-2/
        https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
    .OUTPUTS
        A [psobject] containing the current PowerShell logging settings
    .EXAMPLE
        Get-vlPowerShellLogging
    #>

   param ()

   process {
      $riskScore = 20

      try {
         $transcriptionStatus = Get-vlPowerShellLoggingTranscriptionStatus
         $scriptBlockStatus = Get-vlPowerShellLoggingScriptBlockStatus
         $moduleLoggingStatus = Get-vlPowerShellLoggingModuleLogging

         $score = 10
         $result = [PSCustomObject]@{
            Transcription = $transcriptionStatus
            ScriptBlock   = $scriptBlockStatus
            ModuleLogging = $moduleLoggingStatus
         }

         if (($transcriptionStatus -eq $false) -and ($scriptBlockStatus -eq $false) -and ($moduleLoggingStatus -eq $false)) {
            $score = 8
         }
         elseif (($transcriptionStatus -eq $true ) -and ($scriptBlockStatus -eq $true ) -and ($moduleLoggingStatus -eq $true )) {
            $score = 10
         }
         else {
            $score = 9
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
      catch {

         return New-vlErrorObject -context $_
      }
      finally {

      }
   }

}

Function Get-vlJEACheck {
   <#
    .SYNOPSIS
        Checks if Just Enough Administration (JEA) is enabled
    .DESCRIPTION
        Checks if Just Enough Administration (JEA) is enabled
    .LINK
        https://uberagent.com
    .OUTPUTS
        Returns true if JEA is enabled, false otherwise
    .EXAMPLE
        Get-vlJEACheck
    #>

   param ()

   process {
      # check if WinRM service is running
      $winrm = Get-Service -Name WinRM

      if ($winrm.Status -ne "Running") {
         return $false
      }

      # check if there are any JEA configurations apart from the default ones
      $jeaSessions = Get-PSSessionConfiguration -ErrorAction Stop | Where-Object { $_.Name.ToLower() -notlike 'microsoft.*' }

      if ($jeaSessions.Count -eq 0) {
         return $false
      }
      else {
         return $true
      }
   }
}


function Get-vlPowerShellCheck {
   #Start-Sleep -Seconds 15
   <#
    .SYNOPSIS
        Function that performs the PowerShell check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the PowerShell check and returns the result to the uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlPowerShellCheck
    #>

   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   # disable this check for Windows 7 since Get-WindowsOptionalFeature is not available
   if (($params.Contains("all") -or $params.Contains("PSLMV2"))) {
      $powerShellV2 = Get-vlPowerShellV2Status
      $Output += [PSCustomObject]@{
         Name         = "PSLMV2"
         DisplayName  = "PowerShell V2"
         Description  = "This test verifies the status of PowerShell version 2. PowerShell V2 is a deprecated version of the scripting language and is known to contain several security vulnerabilities and weaknesses in security design."
         Score        = $powerShellV2.Score
         ResultData   = $powerShellV2.Result
         RiskScore    = $powerShellV2.RiskScore
         ErrorCode    = $powerShellV2.ErrorCode
         ErrorMessage = $powerShellV2.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("PSLMRemoting")) {
      $powerShellRemoting = Get-vlPowerShellRemotingStatus
      $Output += [PSCustomObject]@{
         Name         = "PSLMRemoting"
         DisplayName  = "PowerShell Remoting"
         Description  = "This test examines the status of PowerShell Remoting and Just Enough Administration (JEA). PowerShell Remoting is a feature that enables remote administration of computers. While PowerShell Remoting can be a powerful tool for system administrators, enabling it can introduce potential security risks if not managed properly. The use of Just Enough Administration (JEA) is recommended, it is a security technology that can control permissions and limit functionality of PowerShell Remoting instances."
         Score        = $powerShellRemoting.Score
         ResultData   = $powerShellRemoting.Result
         RiskScore    = $powerShellRemoting.RiskScore
         ErrorCode    = $powerShellRemoting.ErrorCode
         ErrorMessage = $powerShellRemoting.ErrorMessage
      }
   }

   <# this test will always return true, because the script won't work in other modes
   if ($params.Contains("all") -or $params.Contains("PSLMCL")) {
      $powerShellMode = Get-vlPowerShellCL
      $Output += [PSCustomObject]@{
         Name         = "PSLMCL"
         DisplayName  = "PowerShell common language mode"
         Description  = "Checks if PowerShell Common Language Mode is enabled"
         Score        = $powerShellMode.Score
         ResultData   = $powerShellMode.Result
         RiskScore    = $powerShellMode.RiskScore
         ErrorCode    = $powerShellMode.ErrorCode
         ErrorMessage = $powerShellMode.ErrorMessage
      }
   }
   #>

   if ($params.Contains("all") -or $params.Contains("PSLMPolicy")) {
      $powerShellExecutionPolicy = Get-vlPowerShellExecutionPolicy
      $Output += [PSCustomObject]@{
         Name         = "PSLMPolicy"
         DisplayName  = "PowerShell policy - Machine"
         Description  = "This test verifies the PowerShell Execution Policy, a security feature in PowerShell that determines the conditions under which PowerShell loads configuration files and runs scripts. For example, an unrestricted policy could allow a malicious script to run without any warnings or prompts, potentially leading to unauthorized system changes or data breaches. We recommend using at least the RemoteSigned policy."
         Score        = $powerShellExecutionPolicy.Score
         ResultData   = $powerShellExecutionPolicy.Result
         RiskScore    = $powerShellExecutionPolicy.RiskScore
         ErrorCode    = $powerShellExecutionPolicy.ErrorCode
         ErrorMessage = $powerShellExecutionPolicy.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("PSLMLogging")) {
      $powerShellLogging = Get-vlPowerShellLogging
      $Output += [PSCustomObject]@{
         Name         = "PSLMLogging"
         DisplayName  = "PowerShell logging"
         Description  = "This test verifies the status of PowerShell Logging, a feature in PowerShell that records the details of PowerShell commands executed on a system."
         Score        = $powerShellLogging.Score
         ResultData   = $powerShellLogging.Result
         RiskScore    = $powerShellLogging.RiskScore
         ErrorCode    = $powerShellLogging.ErrorCode
         ErrorMessage = $powerShellLogging.ErrorMessage
      }
   }

   Write-Output $output
}

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlPowerShellCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIotAYJKoZIhvcNAQcCoIIopTCCKKECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8XSFlKsENbPKU
# RnrrCP/eOhdQpWezrlrc+01LxbCnjaCCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggcBMIIE6aADAgECAhAP47Ki0imEqa3MI1tkbzHeMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE0MDAwMDAwWhcNMjcwNTEz
# MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0Zsb3JpZGExGDAWBgNV
# BAcTD0ZvcnQgTGF1ZGVyZGFsZTEdMBsGA1UEChMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4xDzANBgNVBAsTBkNpdHJpeDEdMBsGA1UEAxMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDWvV/OH9/sYPfeiQAh
# eDNU6vKMQlp+6UDbpI629yfSkJFN8YHaKLwTBL7o8njOMKdbFOSC1LwWh04pGV0Z
# DoCwXTOmzvXm10J2D6a6FKt6mZSKpwzI9RHbU8r26rhU0YU3ikAVDjTwHj44QHeL
# 0znzOlAAxzglEvpCOjHmluKMmaGqFtMdshrC4JPHjSS3Ksy2CSt5zNV88eEoU51v
# MsV/mN7wwnS8pfvFX+1J0dbHxcizG8HAeP66DG9Sedi1Tzm9beBcgYR4IMLXEe6B
# ac2y1AhOc+qFAWhj7ayMy3Mhxk4EZbXVGDP3n+GjiBUnWEfFu3DSucBi6uID+d/r
# 1mkT00hADT/aC2eT/Q/DEm+zVEuOQduX0YmBSe3anfTVLcDieVw/pI60U/e/4L8p
# JDgDwDziLIFKogXRtQYnV9fn3PqMisEigo22HCU6ieJq2lkPb6AZhdSjgFEz242t
# uDwfstvbn6tiZUXa6HggVbPZVZXTUFKhBsC8WE7VdNVd2HECAwEAAaOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBRbcl4N
# sqHrugpyuVoA9I4eak86SjA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAba1In5WIqLU6LE1uLOVwCllMLOAVeWUb1wPJ2fugaH891Oy42VUvND/cxd2L
# Fl8aIBEn9snnxJpFlyoLG3eNZYPLvSHgFuWlBlHkp4cwL4hihgjXQvRdhKFINE87
# 7RCLg9aNh8LzxNs9ciMM/sho/+dv2cojZPBqCZBxL9Fk+irRkZNUwgtR6/F2ijMu
# BnbGI9M24J6QqGj81wOSIrldQ/6hFGhDG0h58VZ+s8W0Bl4gf6P7lxZb8t0biBD5
# uijZxf9Ny4grACnIY9YQQRAH9k4QcBofNvro4U20OQIjRP7i7acQ5+SyFBzIn5Ko
# MkspCGz8VkvefMDgj91dXJSBBZlWIPRkRRETTbZhq83zjZNeupLCDMGJg1hUvtOu
# Is+Wn3+1/K5jrBK9dW3BukExwO/HpumRJ5T3gCPeCz8015XXsvixZSJPW91U1zwt
# +srK0tvNKBIPGSaVfJkLsf5iKeTQVCZtR8Y17ZNX0rLU3DeBytc3d3jfafqeVlih
# YrCTmQp9FiL9gzlr4OxVghgP6mCki7B/0SJXGg+tR1AOp12T5h/FSelSoPgECFhn
# aWQct57F/q6gSrTxVxwm1/xjb2EehEriH0H+TSJ+Jhu+z4y/Slc3qzt3haC8GjEU
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxghpRMIIaTQIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggaww
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINlnrI4GJ1jXBCvJyqU00J5hYQKu7NZ4
# 7eAVW7FicqVXMEAGCisGAQQBgjcCAQwxMjAwoC6ALABQAG8AdwBlAHIAUwBoAGUA
# bABsAC0ATQBhAGMAaABpAG4AZQAuAHAAcwAxMA0GCSqGSIb3DQEBAQUABIIBgEjL
# iKqik5//QBUjp1/p8xYkesZ2dM4thfJ5E14XR/dm5GSoxKLQySXRZBB7U58Hm1ae
# tRdy3oLW5iN16r3oJ3kNQKYES/0w0rNTx+91XWmVfg8dBb2UhVbN2FQFrBuTHDJ3
# lYaiJvpNYOxzgR6ubyhGPpbcU27mk4TunhFEHNmX5rtPnMcjbKKIn9Oq/lcZV2GV
# MGqYcPdDj0vJ3XTYyhvvMD0684YbxsfpVZ3+Pz7dUV7ROzc5ICgMgaEMwhqhGg0h
# eAAlMeTsQONRxejr8oNxvN8VxiWFYIz2L2BFq4+TpslGtHT8bPavl039AvhJSz8k
# IW40IlJ4k3pfqAkhj/nRb8ZYwdWl7d9A+9ftvaV3KYAbM/Nh72rP9x+ro1rFvWwa
# qES2OLElQOm36AFc5th8K855lpHiSiG6z70sLOkrbSNKJlfZjx2Unb0MqzLjsAqs
# Kwyp8ZAvHeZmFpdXFaInirmPl3AdF0bbtkRu6XJUqd+WKDom1ocZoVm9syTHDaGC
# F3YwghdyBgorBgEEAYI3AwMBMYIXYjCCF14GCSqGSIb3DQEHAqCCF08wghdLAgED
# MQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG
# /WwHATAxMA0GCWCGSAFlAwQCAQUABCDxOpaQIreHFWaAHascC56ITZgvMTyqdzh4
# 77Fu4ghgKQIQJpyRD9WheGGEZMMYFwcMFhgPMjAyNjA4MjUwNzQyMTZaoIITOjCC
# Bu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhE
# aWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAy
# MDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNl
# cnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/
# hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7
# zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0D
# vbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+If
# xiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYev
# vOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZr
# eiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz
# 8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVC
# GZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssosz
# QyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOz
# aQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlw
# CUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
# FgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQ
# VvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMI
# MIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAy
# NUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIw
# MjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkq
# hkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+F
# ERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQ
# uPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9kt
# x0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xe
# jEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0
# fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu
# /3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTl
# QJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaeh
# r0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK
# +At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1
# Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcw
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIFjTCCBHWg
# AwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcN
# MjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEp
# pz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+
# n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYykt
# zuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw
# 2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6Qu
# BX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC
# 5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK
# 3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3
# IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEP
# lAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98
# THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3l
# GwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1Ud
# HwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEB
# DAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi
# 7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqL
# sl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo
# 0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVg
# HAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnw
# toeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDfDCCA3gCAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwODI1MDc0MjE2WjAr
# BgsqhkiG9w0BCRACDDEcMBowGDAWBBTdYjCshgotMGvaOLFoeVIwB/tBfjAvBgkq
# hkiG9w0BCQQxIgQgF9OrwPPr4eB24cyTNG1UxjHG6uZS7cShSHgqVO3UZygwNwYL
# KoZIhvcNAQkQAi8xKDAmMCQwIgQgSqA/oizXXITFXJOPgo5na5yuyrM/420mmqM0
# 8UYRCjMwDQYJKoZIhvcNAQEBBQAEggIAO7XrSo/0A2xsXGb/miV1g7b40U091Oe8
# 5Mi5+2pPeWl060Ox9RA2gY1oD1AjFvh/xw+/eiIcK7+Qhw4gyZtiJ4Rdd3g9JJnt
# aVqko6+6T5alHKNoHTr/obZQ6h+KuBS1VZQUCHdRrWITXztSRj0BtXY9+OwV0cIx
# ZvHEZx1QhHbGjHu78jppHBXrJrEfFrZezgkW43lQlFgVNBSWTlFATkFXt0zh/oEZ
# yqCE6B7kY08n0xcu63rsl4CthzrbuT7shKmM7A8gdQtI6jgIpZ7g//unhGZPuBaK
# P1MCBkm8muVOv8SJBu2+TkbkWfkEQg7mJnPtMwAF3+WCcrMrBapRe8n7nxafxtxN
# Fah8mJLoScr/YrxP1ki2pdXORGwBYavo9W4KHQgbgBh3HsnLcIANpWtQ6+ilLyx8
# 6RtJBfBOzTj8BAvGT53BfbwwE2W+7NS9O7jZupB5ENKZgFmeAXcyBnsOz/E9oZar
# 9/7ia3inGhaQam9IwyGZk8oXspkIgVHreU6k3jIlOfUIIqKOX8Bmb/8ZEq6esKPc
# baAS/pvKEqYD1rnSgzy75EJWmvCS7dMJa61TWUiU19vzPwQdD9LRczNJWfH450uq
# aJRbpF502aIzByl7wvb4HrFCsbSIAaW2XRgUTJRZLMLm5twLHpMFO5aY6XxfvFMT
# 68Qp/YEPlLA=
# SIG # End signature block
