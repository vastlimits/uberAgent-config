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
         $currentPowerShellVersion = $PSVersionTable.PSVersion.ToString()

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
        https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/
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
            ExecutionPolicy = "Undefined"
         }

         $policys = Get-ExecutionPolicy -List
         $highestPolicy = "Undefined"

         # go from lowest to highest
         # first check LocalMachine policy
         $policy = $policys | Where Scope -eq "LocalMachine"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "LocalMachine"
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         # check CurrentUser policy
         $policy = $policys | Where Scope -eq "CurrentUser"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "CurrentUser"
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         # check UserPolicy policy
         $policy = $policys | Where Scope -eq "UserPolicy"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "UserPolicy"
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         # check MachinePolicy policy
         $policy = $policys | Where Scope -eq "MachinePolicy"

         if ($policy.ExecutionPolicy -ne "Undefined") {
            $highestPolicy = "MachinePolicy"
            $result.ExecutionPolicy = $policy.ExecutionPolicy.ToString()
         }

         $LMrisk = 80
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

         if ($highestPolicy -eq "MachinePolicy") {
            return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
         }
         elseif ($highestPolicy -eq "UserPolicy") {
            return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
         }
         elseif ($highestPolicy -eq "CurrentUser") {
            return New-vlResultObject -result $result -score $LMLevel -riskScore $LMrisk
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

   $result = $false

   try {
      $transcription = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\PowerShell\Transcription" -Value "EnableTranscripting" -IncludePolicies $true
      if ( $transcription -eq 1) {
         $result = $true
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


   $result = $false

   try {
      $scriptBlockLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Value "EnableScriptBlockLogging" -IncludePolicies $true
      if ($scriptBlockLogging -eq 1) {
         $result = $true
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

   $result = $false

   try {
      $enableModuleLogging = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\PowerShell\ModuleLogging" -Value "EnableModuleLogging" -IncludePolicies $true
      if ($enableModuleLogging -eq 1) {
         $result = $true
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

         if (($transcriptionStatus -eq $false) -and ($scriptBlockStatus -eq $false) -and ($moduleLoggingStatus -eq $false)) {
            $score = 8
         }
         elseif (($transcriptionStatus -eq $true ) -and ($scriptBlockStatus -eq $true ) -and ($moduleLoggingStatus -eq $true )) {
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

   if ($params.Contains("all") -or $params.Contains("PSLMV2")) {
      $powerShellV2 = Get-vlPowerShellV2Status
      $Output += [PSCustomObject]@{
         Name         = "PSLMV2"
         DisplayName  = "PowerShell V2"
         Description  = "Checks if PowerShell V2 is enabled"
         Score        = $powerShellV2.Score
         ResultData   = $powerShellV2.Result
         RiskScore    = 60
         ErrorCode    = $powerShellV2.ErrorCode
         ErrorMessage = $powerShellV2.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("PSLMRemoting")) {
      $powerShellRemoting = Get-vlPowerShellRemotingStatus
      $Output += [PSCustomObject]@{
         Name         = "PSLMRemoting"
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
   <# disabled for now due to limits of the current implementation
   if ($params.Contains("all") -or $params.Contains("PSLMCL")) {
      $powerShellMode = Get-vlPowerShellCL
      $Output += [PSCustomObject]@{
         Name         = "PSLMCL"
         DisplayName  = "PowerShell common language mode"
         Description  = "Checks if PowerShell Common Language Mode is enabled"
         Score        = 10
         ResultData   = $powerShellMode.Result
         RiskScore    = 0
         ErrorCode    = $powerShellMode.ErrorCode
         ErrorMessage = $powerShellMode.ErrorMessage
      }
   }
   #>

   if ($params.Contains("all") -or $params.Contains("PSLMPolicy")) {
      $powerShellExecutionPolicy = Get-vlPowerShellExecutionPolicy
      $Output += [PSCustomObject]@{
         Name         = "PSLMPolicy"
         DisplayName  = "PowerShell policy"
         Description  = "Checks and evaluates the PowerShell Execution Policy"
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