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
         Description  = "This test verifies the PowerShell Execution Policy, a security feature in PowerShell that determines the conditions under which PowerShell loads configuration files and runs scripts. For example, an unrestricted policy could allow a malicious script to run without any warnings or prompts, potentially leading to unauthorized system changes or data breaches. We recommend using at least the RemoteSigned policy."
         Score        = $powerShellExecutionPolicy.Score
         ResultData   = $powerShellExecutionPolicy.Result
         RiskScore    = $powerShellExecutionPolicy.RiskScore
         ErrorCode    = $powerShellExecutionPolicy.ErrorCode
         ErrorMessage = $powerShellExecutionPolicy.ErrorMessage
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
