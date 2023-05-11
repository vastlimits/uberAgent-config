#Requires -RunAsAdministrator
#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlPowerShellV2Status {
   <#
    .SYNOPSIS
        Performs a check if PowerShell V2 is installed on the system
    .DESCRIPTION
        Performs a check if PowerShell V2 is installed on the system
    .LINK
        https://uberagent.com
    .NOTES
        This function requires elevated privilegs
        https://www.tenforums.com/tutorials/111654-enable-disable-windows-powershell-2-0-windows-10-a.html
    .OUTPUTS
        A [psobject] containing the status of the PowerShell V2 installation
    .EXAMPLE
        Get-vlPowerShellV2Status
    #>

   process {
      try {
         $currentPowerShellVersion = Get-vlPowerShellVersion | Select-Object -ExpandProperty result | Select-Object -ExpandProperty Version

         #check if PowerShell V2 is installed on the system
         $installationStatus = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2

         $result = [PSCustomObject]@{
            PowerShellV2Enabled = ($installationStatus.State -eq "Enabled")
            DefaultVersion      = $currentPowerShellVersion
         }

         if ($result.PowerShellV2Enabled) {
            return New-vlResultObject -result $result -score 4
         }
         else {
            return New-vlResultObject -result $result -score 10
         }
      }
      catch {

         return New-vlErrorObject($_)
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
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.3
    .EXAMPLE
        Get-vlPowerShellCL
    #>

   process {
      try {
         $result = [PSCustomObject]@{
            LanguageMode = $ExecutionContext.SessionState.LanguageMode.ToString()
         }

         return New-vlResultObject -result $result
      }
      catch {

         return New-vlErrorObject($_)
      }
   }

}

function Get-vlPowerShellVersion {
   <#
    .SYNOPSIS
        Checks the current PowerShell version
    .DESCRIPTION
        Checks the current PowerShell version
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell version
    .EXAMPLE
        Get-vlPowerShellVersion
    #>

   param ()

   process {
      try {
         $result = [PSCustomObject]@{
            Version = $PSVersionTable.PSVersion.ToString()
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

Function Get-vlPowerShellRemotingStatus {
   <#
    .SYNOPSIS
        Checks the current PowerShell remoting status
    .DESCRIPTION
        Checks the current PowerShell remoting status
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the current PowerShell remoting status
    .EXAMPLE
        Get-vlPowerShellRemotingStatus
    #>

   try {
      $serviceStatus = Get-Service -Name WinRM | Select-Object -ExpandProperty Status

      #if the service is not running, remoting is disabled
      if ($serviceStatus -ne "Running") {
         $result = [PSCustomObject]@{
            RemotingEnabled = $false
            JEAEnabled      = $false
         }

         return New-vlResultObject -result $result -score 10 -riskScore 50
      }

      # Try to open a session to localhost
      $session = New-PSSession -ComputerName localhost

      # Close the session
      Remove-PSSession $session

      # Check if JEA is enabled
      $JEAState = Get-vlJEACheck

      # If the session is opened, remoting is enabled
      $result = [PSCustomObject]@{
         RemotingEnabled = $true
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
            ExecutionPolicyLM = "Undefined"
            ExecutionPolicyCU = "Undefined"
         }

         $policys = Get-ExecutionPolicy -List
         $highestPolicy = "Undefined"

         # go from lowest to highest
         # first check LocalMachine policy
         $policy = $policys | Where Scope -eq "LocalMachine"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "LocalMachine"
            $result.ExecutionPolicyLM = $policy.ExecutionPolicy.ToString()
         }

         # check CurrentUser policy
         $policy = $policys | Where Scope -eq "CurrentUser"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "CurrentUser"
            $result.ExecutionPolicyCU = $policy.ExecutionPolicy.ToString()
         }

         # check UserPolicy policy
         $policy = $policys | Where Scope -eq "UserPolicy"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "UserPolicy"
            $result.ExecutionPolicyCU = $policy.ExecutionPolicy.ToString()
         }

         # check MachinePolicy policy
         $policy = $policys | Where Scope -eq "MachinePolicy"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "MachinePolicy"
            $result.ExecutionPolicyLM = $policy.ExecutionPolicy.ToString()
         }

         $LMrisk = 80
         $CUrisk = 80
         $LMLevel = 2
         $CULevel = 2

         # Level 0: Unrestricted
         # Level 1: Bypass
         # Level 2: RemoteSigned
         # Level 3: AllSigned
         # Level 4: Restricted
         # Level 5: Undefined

         # check $result.ExecutionPolicyLM and $result.ExecutionPolicyCU and set $LMLevel and $CULevel accordingly
         switch ($result.ExecutionPolicyLM) {
            "Unrestricted" {
               $LMLevel = 2
               $LMrisk = 80
            }
            "Bypass" {
               $LMLevel = 2
               $LMrisk = 80
            }
            "RemoteSigned" {
               $LMLevel = 6
               $LMrisk = 40
            }
            "AllSigned" {
               $LMLevel = 8
               $LMrisk = 20
            }
            "Restricted" {
               $LMLevel = 10
               $LMrisk = 20
            }
            "Undefined" {
               $LMLevel = 10
               $LMrisk = 20
            }
         }

         switch ($result.ExecutionPolicyCU) {
            "Unrestricted" {
               $CULevel = 2
               $CUrisk = 80
            }
            "Bypass" {
               $CULevel = 2
               $CUrisk = 80
            }
            "RemoteSigned" {
               $CULevel = 6
               $CUrisk = 40
            }
            "AllSigned" {
               $CULevel = 8
               $CUrisk = 20
            }
            "Restricted" {
               $CULevel = 10
               $CUrisk = 20
            }
            "Undefined" {
               $CULevel = 10
               $CUrisk = 20
            }
         }

         if ($highestPolicy -eq "MachinePolicy") {
            return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
         }
         elseif ($highestPolicy -eq "UserPolicy") {
            return New-vlResultObject -result $result -score $CULevel -riskScore $CUrisk
         }
         elseif ($highestPolicy -eq "CurrentUser") {
            return New-vlResultObject -result $result -score $CULevel -riskScore $CUrisk
         }
         elseif ($highestPolicy -eq "LocalMachine") {
            return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
         }

         $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
         <#
                Work Station (1)
                Domain Controller (2)
                Server (3)
            #>

         # If the execution policy in all scopes is Undefined, the effective execution policy is Restricted for Windows clients and RemoteSigned for Windows Server.
         if ($osInfo.ProductType -eq 1) {
            return New-vlResultObject -result $result -score 10 -riskScore 0
         }
         else {
            return New-vlResultObject -result $result -score 6 -riskScore 40
         }
      }
      catch {

         return New-vlErrorObject($_)
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

   $result = [PSCustomObject]@{
      Registry    = $false
      GroupPolicy = $false
   }

   try {
      $transcription = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Value "EnableTranscripting"
      if ( $transcription -eq 1) {
         $result.Registry = $true
      }

      $transcription = (Get-GPRegistryValue -Name "EnableTranscripting" -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell").Value
      if ($transcription -eq 1) {
         $result.GroupPolicy = $true
      }
   }
   catch {

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


   $result = [PSCustomObject]@{
      Registry    = $false
      GroupPolicy = $false
   }

   try {
      $scriptBlockLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Value "EnableScriptBlockLogging"
      if ($scriptBlockLogging -eq 1) {
         $result.Registry = $true
      }

      $scriptBlockLogging = (Get-GPRegistryValue -Name "EnableScriptBlockLogging" -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell").Value
      if ($scriptBlockLogging -eq 1) {
         $result.GroupPolicy = $true
      }
   }
   catch {

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

   $result = [PSCustomObject]@{
      Registry    = $false
      GroupPolicy = $false
   }

   try {
      $scriptBlockLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Value "EnableModuleLogging"
      if ($scriptBlockLogging -eq 1) {
         $result.Registry = $true
      }

      $scriptBlockLogging = (Get-GPRegistryValue -Name "EnableModuleLogging" -Key "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell").Value
      if ($scriptBlockLogging -eq 1) {
         $result.GroupPolicy = $true
      }
   }
   catch {

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
        https://uberagent.com
        https://adamtheautomator.com/powershell-logging-2/
        https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html
    .OUTPUTS
        A [psobject] containing the current PowerShell logging settings
    .EXAMPLE
        Get-vlPowerShellLogging
    #>

   param ()

   process {
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

         if (($transcriptionStatus.Registry -eq $false -and $transcriptionStatus.GroupPolicy -eq $false) -and ($scriptBlockStatus.Registry -eq $false -and $scriptBlockStatus.GroupPolicy -eq $false) -and ($moduleLoggingStatus.Registry -eq $false -and $moduleLoggingStatus.GroupPolicy -eq $false)) {
            $score = 8
         }
         elseif (($transcriptionStatus.Registry -eq $true -or $transcriptionStatus.GroupPolicy -eq $true ) -and ($scriptBlockStatus.Registry -eq $true -or $scriptBlockStatus.GroupPolicy -eq $true ) -and ($moduleLoggingStatus.Registry -eq $true -or $moduleLoggingStatus.GroupPolicy -eq $true )) {
            $score = 10
         }
         else {
            $score = 9
         }

         return New-vlResultObject -result $result -score $score
      }
      catch {

         return New-vlErrorObject($_)
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

      # check if there are any JEA sessions
      $jeaSessions = Get-PSSessionConfiguration | Where-Object { $_.RunAsVirtualAccount -eq $true }
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

   if ($params.Contains("all") -or $params.Contains("PSV2")) {
      $powerShellV2 = Get-vlPowerShellV2Status
      $Output += [PSCustomObject]@{
         Name         = "PSV2"
         DisplayName  = "PowerShell V2"
         Description  = "Checks if PowerShell V2 is enabled"
         Score        = $powerShellV2.Score
         ResultData   = $powerShellV2.Result
         RiskScore    = 60
         ErrorCode    = $powerShellV2.ErrorCode
         ErrorMessage = $powerShellV2.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("PSRemoting")) {
      $powerShellRemoting = Get-vlPowerShellRemotingStatus
      $Output += [PSCustomObject]@{
         Name         = "PSRemoting"
         DisplayName  = "PowerShell Remoting"
         Description  = "Checks if PowerShell remoting is enabled"
         Score        = $powerShellRemoting.Score
         ResultData   = $powerShellRemoting.Result
         RiskScore    = $powerShellRemoting.RiskScore
         ErrorCode    = $powerShellRemoting.ErrorCode
         ErrorMessage = $powerShellRemoting.ErrorMessage
      }
   }

   ## If CL is enabled, the test cannot be run
   if ($params.Contains("all") -or $params.Contains("PSCL")) {
      $powerShellMode = Get-vlPowerShellCL
      $Output += [PSCustomObject]@{
         Name         = "PSCL"
         DisplayName  = "PowerShell common language mode"
         Description  = "Checks if PowerShell Common Language Mode is enabled"
         Score        = 10
         ResultData   = $powerShellMode.Result
         RiskScore    = 0
         ErrorCode    = $powerShellMode.ErrorCode
         ErrorMessage = $powerShellMode.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("PSPolicy")) {
      $powerShellExecutionPolicy = Get-vlPowerShellExecutionPolicy
      $Output += [PSCustomObject]@{
         Name         = "PSPolicy"
         DisplayName  = "PowerShell policy"
         Description  = "Checks and evaluates the PowerShell Execution Policy"
         Score        = $powerShellExecutionPolicy.Score
         ResultData   = $powerShellExecutionPolicy.Result
         RiskScore    = $powerShellExecutionPolicy.RiskScore
         ErrorCode    = $powerShellExecutionPolicy.ErrorCode
         ErrorMessage = $powerShellExecutionPolicy.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("PSLogging")) {
      $powerShellLogging = Get-vlPowerShellLogging
      $Output += [PSCustomObject]@{
         Name         = "PSLogging"
         DisplayName  = "PowerShell logging"
         Description  = "Checks if PowerShell Logging is enabled"
         Score        = $powerShellLogging.Score
         ResultData   = $powerShellLogging.Result
         RiskScore    = 20
         ErrorCode    = $powerShellLogging.ErrorCode
         ErrorMessage = $powerShellLogging.ErrorMessage
      }
   }

   Write-Output $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlPowerShellCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBPug8BaK3WBUD3
# cQ7/5cYHMBTGzPNltjVkT8QP7sDgMKCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
# CDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8G
# A1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAe
# Fw0xNjA2MjQyMDQ0MzBaFw0zMTA2MjQyMDQ0MzBaMHgxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENv
# cnAxNDAyBgNVBAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBD
# QSBSU0EgUjEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCfgxNzqrDG
# bSHL24t6h3TQcdyOl3Ka5LuINLTdgAPGL0WkdJq/Hg9Q6p5tePOf+lEmqT2d0bKU
# Vz77OYkbkStW72fL5gvjDjmMxjX0jD3dJekBrBdCfVgWQNz51ShEHZVkMGE6ZPKX
# 13NMfXsjAm3zdetVPW+qLcSvvnSsXf5qtvzqXHnpD0OctVIFD+8+sbGP0EmtpuNC
# GVQ/8y8Ooct8/hP5IznaJRy4PgBKOm8yMDdkHseudQfYVdIYyQ6KvKNc8HwKp4WB
# wg6vj5lc02AlvINaaRwlE81y9eucgJvcLGfE3ckJmNVz68Qho+Uyjj4vUpjGYDdk
# jLJvSlRyGMwnh/rNdaJjIUy1PWT9K6abVa8mTGC0uVz+q0O9rdATZlAfC9KJpv/X
# gAbxwxECMzNhF/dWH44vO2jnFfF3VkopngPawismYTJboFblSSmNNqf1x1KiVgMg
# Lzh4gL32Bq5BNMuURb2bx4kYHwu6/6muakCZE93vUN8BuvIE1tAx3zQ4XldbyDge
# VtSsSKbt//m4wTvtwiS+RGCnd83VPZhZtEPqqmB9zcLlL/Hr9dQg1Zc0bl0EawUR
# 0tOSjAknRO1PNTFGfnQZBWLsiePqI3CY5NEv1IoTGEaTZeVYc9NMPSd6Ij/D+KNV
# t/nmh4LsRR7Fbjp8sU65q2j3m2PVkUG8qQIDAQABo4H7MIH4MA8GA1UdEwEB/wQF
# MAMBAf8wHwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUNplkwMAYIKwYBBQUH
# AQEEJDAiMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcHMuc3NsLmNvbTARBgNVHSAE
# CjAIMAYGBFUdIAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwOwYDVR0fBDQwMjAwoC6g
# LIYqaHR0cDovL2NybHMuc3NsLmNvbS9zc2wuY29tLXJzYS1Sb290Q0EuY3JsMB0G
# A1UdDgQWBBRUwv4QlQCTzWr158DX2bJLuI8M4zAOBgNVHQ8BAf8EBAMCAYYwDQYJ
# KoZIhvcNAQELBQADggIBAPUPJodwr5miyvXWyfCNZj05gtOII9iCv49UhCe204MH
# 154niU2EjlTRIO5gQ9tXQjzHsJX2vszqoz2OTwbGK1mGf+tzG8rlQCbgPW/M9r1x
# xs19DiBAOdYF0q+UCL9/wlG3K7V7gyHwY9rlnOFpLnUdTsthHvWlM98CnRXZ7WmT
# V7pGRS6AvGW+5xI+3kf/kJwQrfZWsqTU+tb8LryXIbN2g9KR+gZQ0bGAKID+260P
# Z+34fdzZcFt6umi1s0pmF4/n8OdX3Wn+vF7h1YyfE7uVmhX7eSuF1W0+Z0duGwdc
# +1RFDxYRLhHDsLy1bhwzV5Qe/kI0Ro4xUE7bM1eV+jjk5hLbq1guRbfZIsr0WkdJ
# LCjoT4xCPGRo6eZDrBmRqccTgl/8cQo3t51Qezxd96JSgjXktefTCm9r/o35pNfV
# HUvnfWII+NnXrJlJ27WEQRQu9i5gl1NLmv7xiHp0up516eDap8nMLDt7TAp4z5T3
# NmC2gzyKVMtODWgqlBF1JhTqIDfM63kXdlV4cW3iSTgzN9vkbFnHI2LmvM4uVEv9
# XgMqyN0eS3FE0HU+MWJliymm7STheh2ENH+kF3y0rH0/NVjLw78a3Z9UVm1F5VPz
# iIorMaPKPlDRADTsJwjDZ8Zc6Gi/zy4WZbg8Zv87spWrmo2dzJTw7XhQf+xkR6Od
# MIIG8zCCBNugAwIBAgIQfYHMItEnwWprKIwmkVmsVDANBgkqhkiG9w0BAQsFADB4
# MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24x
# ETAPBgNVBAoMCFNTTCBDb3JwMTQwMgYDVQQDDCtTU0wuY29tIENvZGUgU2lnbmlu
# ZyBJbnRlcm1lZGlhdGUgQ0EgUlNBIFIxMB4XDTIzMDMwNzIyNTIyNloXDTI2MDMw
# NjIyNTIyNlowfDELMAkGA1UEBhMCREUxHDAaBgNVBAgME05vcmRyaGVpbi1XZXN0
# ZmFsZW4xGTAXBgNVBAcMEE1vbmhlaW0gYW0gUmhlaW4xGTAXBgNVBAoMEHZhc3Qg
# bGltaXRzIEdtYkgxGTAXBgNVBAMMEHZhc3QgbGltaXRzIEdtYkgwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDmsmxRhHnZ47SQfWJmJje0vVjTVhDfA15d
# Q99NkNBuxZV4F+zSdMuCH+CT77aJIa6fbQQzQCs5Z2bfia82RXAKgC9SPALFAdLq
# 3OyQ8IICyivsVn4IkLzGuEJPETDHWfRAJmICajFqyxX6DXcuOmxIm3c/s3F413DO
# uBn+oTebJu1lk/Mp0L+pd1MYnY3rKEsv+FuXE6valQqJRrIlkQA7sC2ji6A4tsA8
# 9NxK7IQlGIh4P2sEBq9YVrXOpCoxuzGC9zDwE1et1BrcviHr2z9AEfOD5te7CAbZ
# CukDEri7zskt8pL5vT+Djdn+u5yo689L3QcFG4JVs0AIPmxt91l8UJDX/I2oKBz8
# 4KuZGLExHDYETtIiCjB0gKBOWl4kojgqewBe8cL0HNcuCxmfMTubepSTF3R3UOrv
# bcSP2W34eJ353EEuCZMmkgQnj+Cu+g7fY379ddWO24rS9gonoSrsoCK7iVlGPLjz
# whKRe6S2vpFpsoEPo9bhdP5w1aCf/TQZixffdQSB2gFgGivgXjZ60ld5XUOG5eyZ
# ow6vEzKq7Bqnipd7t8xgBq6jIQ0y2fFS8o656pZvf7fvZ7bMM47uBXN9812/R4mX
# Zw6kvsH2k5YKZh97i9oBa+XCSeFVecFT5JY9uRj3SutCj5JvxsX5z5FH4qVedwse
# PYM6LtsztwIDAQABo4IBczCCAW8wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBRU
# wv4QlQCTzWr158DX2bJLuI8M4zBYBggrBgEFBQcBAQRMMEowSAYIKwYBBQUHMAKG
# PGh0dHA6Ly9jZXJ0LnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJT
# QS00MDk2LVIxLmNlcjBRBgNVHSAESjBIMAgGBmeBDAEEATA8BgwrBgEEAYKpMAED
# AwEwLDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuc3NsLmNvbS9yZXBvc2l0b3J5
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDME0GA1UdHwRGMEQwQqBAoD6GPGh0dHA6Ly9j
# cmxzLnNzbC5jb20vU1NMY29tLVN1YkNBLUNvZGVTaWduaW5nLVJTQS00MDk2LVIx
# LmNybDAdBgNVHQ4EFgQUH4wxTfruqchOioKCaULdd2n1d6AwDgYDVR0PAQH/BAQD
# AgeAMA0GCSqGSIb3DQEBCwUAA4ICAQA+C1FID5jlerfUMR3DnJAe3ngwe/3YaItK
# 40Ccvd2ZG7lwmpho0ITP5EcXvQnkfsL5pGrXT1iRXMYrDgTz6eqtfpyC99F+fUGj
# aLrlOJvtzl1KypxHDRCvZKs2Qc7pceyvDZb+Wb4VrthpOYYTVfI+HWIYLiMH4fKB
# pkxCGLDipaPXHEQ+DNPUs1J7GpVyrh6jyMtfYZSEHz9YACvlT0FHooj7QDIlAX/u
# 6988XxGO8N4LZaaWUcLBb+LlQwiskVg+FXUMTarv7MS/e8ZirVfiHGXtiV9texcf
# 0LepL2nKtbcUTXYLucaW/8G+v0lO1H++K0/ziwqCCdxADzNR3/NGDth9vnLl+UPN
# 4QXCJEaw37RnipOxudFJOMqFSvNvARWNlxHvwgk+dRI5RDLKKSWdCKrC1/svMuG4
# sj+PgtITa3nWNVb56FpB6TXPc04Jqj7aeGcS7IfDKcZKXknVW/ngvZxLuKhdyJrk
# aovWHDjJNX2YuS6mAaw5CJ/5QDnxVD78qn9Zq4uqEg6aEnS1+FPuo42P+78sMuys
# +sjER4hLMrLhXfvwEOOHeweV75IF7rm5zDmZFJv54tJP3vuvNF1opr9ccWzhO3BG
# ufTWS/qKYurtB8uEmbJCH8ltE56bquVL0YRfVwVSV7gyp355x3Ptgu+v8YPDuzn3
# ZJjydk0JATGCAz8wggM7AgEBMIGMMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVU
# ZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNV
# BAMMK1NTTC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBSU0EgUjEC
# EH2BzCLRJ8FqayiMJpFZrFQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgGxqARxhGsGYT
# bjS+m1sbZaf719C7pnMhN0hDAdlm4fswDQYJKoZIhvcNAQEBBQAEggIAbzqvJD44
# i/i9eS0d8qdBYk+z5lklEdTDEkxIXGo4zDRS8onsG9LMlCzrvMGQ16xMczZIcQdw
# JcT3MQo0OnODbZntFgdKCKBEqgdZqhXBusGQg4/yv7n3mcG5w96EeSiijyNeeWwX
# 7y/iJ3ZzWIpCcz9j1Xjm/GK+MHh5m5zjVcefaWqbdt2v3BY7Rpe+Dj7mJJumX1vn
# ZhnvE9vaiqi0DFvigPOu2MGZR7LHOUQ59ieRkNo12aHs3TmGJMDkF7oEVSDuryLg
# De//2njw2heeq/IYmnDhL4aREUT5sQNcVIbmlSLjFlXznb4F1pc1Gk+H5q0cqBS6
# Ykut1SaohoU5DlsPuv6GdA6LvlX5tPAzGIvC9LqttzxT8l+vO/04m+Oml/kiuLIM
# aQF5qohD8ci6CdxEMUdCA6vpkfJjP6GPuVDXANJHzsIsN721DZsKIIYKkHh9lWN0
# ulZMju+te/r/1ZlPakswIvKiWATqqbVGjW3y8iyGn0P5bPUlEU0KgHSFzEEIdlx8
# PS9KWxC6PgCbBP8jR2S9pn+UnvZVtexMQtyWjFW9LfiTf/J8NO2hMq8Ol2OpdIUQ
# NuvSUwIUzczb5bNDG0McijhFlUFMlHfww+B6hqMomHfV2324u2Bh7vC56nKQOg71
# 0kJJW3LI1cIPtaAD9ULaTRftkSHqanIC4w0=
# SIG # End signature block
