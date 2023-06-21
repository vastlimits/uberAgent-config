#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

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
         $active_policy = Get-ExecutionPolicy
         $result = [PSCustomObject]@{
            ExecutionPolicy = $active_policy.ToString()
         }

         $CUrisk = 80
         $CULevel = 2

         # Level 0: Unrestricted
         # Level 1: Bypass
         # Level 2: RemoteSigned
         # Level 3: AllSigned
         # Level 4: Restricted
         # Level 5: Undefined

         switch ($active_policy) {
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

         if ($active_policy -ne "Undefined") {
            return New-vlResultObject -result $result -score $CULevel -riskScore $CUrisk
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

   if ($params.Contains("all") -or $params.Contains("PSCUPolicy")) {
      $powerShellExecutionPolicy = Get-vlPowerShellExecutionPolicy
      $Output += [PSCustomObject]@{
         Name         = "PSCUPolicy"
         DisplayName  = "PowerShell policy"
         Description  = "Checks and evaluates the PowerShell Execution Policy"
         Score        = $powerShellExecutionPolicy.Score
         ResultData   = $powerShellExecutionPolicy.Result
         RiskScore    = $powerShellExecutionPolicy.RiskScore
         ErrorCode    = $powerShellExecutionPolicy.ErrorCode
         ErrorMessage = $powerShellExecutionPolicy.ErrorMessage
      }
   }

   Write-Output $output
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlPowerShellCheck | ConvertTo-Json -Compress)
