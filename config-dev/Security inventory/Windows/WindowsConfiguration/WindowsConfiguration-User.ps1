
. $PSScriptRoot\..\Shared\Helper.ps1 -Force
. $PSScriptRoot\..\Shared\AppLinkHelper.ps1 -Force


function Test-vlBlockedProgram {
   <#
    .SYNOPSIS
        Tests if a program is blocked by the system.
    .DESCRIPTION
        Tests if a program is blocked by the system.
    .OUTPUTS
        A [bool] indicating if the program is blocked or not
    .EXAMPLE
        Test-vlBlockedProgram
    #>

   Param(
      [string]$ProgramPath
   )

   $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
   $processStartInfo.FileName = $ProgramPath
   $processStartInfo.RedirectStandardError = $true
   $processStartInfo.RedirectStandardOutput = $true
   $processStartInfo.UseShellExecute = $false
   $processStartInfo.CreateNoWindow = $true

   $process = New-Object System.Diagnostics.Process
   $process.StartInfo = $processStartInfo

   try {
      $process.Start() | Out-Null
      $process.WaitForExit()

      $exitCode = $process.ExitCode

      if ($exitCode -ne 0) {
         # the program is blocked
         return $true
      }
      else {
         # the program is not blocked
         return $false
      }
   }
   catch {
      # an exception occurred, indicating the program is blocked
      return $true
   }
}

function Get-CheckHTAEnabled {
   <#
    .SYNOPSIS
        Checks if HTA is enabled on the system.
    .DESCRIPTION
        Checks if HTA is enabled on the system.
    .LINK
        https://uberagent.com
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-CheckHTAEnabled
    #>

   try {
      $startProc = ""
      $score = 10
      $riskScore = 80

      #$htaExecuteStatus = Run-vlHtaCode $htacode
      $htaRunBlocked = Test-vlBlockedProgram -ProgramPath "mshta.exe"

      $defaultLink = $true
      $startCmd = [AppLinkHelper]::AssocQueryString(".hta")

      if ($null -ne $startCmd -and $startCmd -ne "") {
         $startProc = (Split-Path $startCmd -Leaf)

         # check if $startProc contains space and if so, get the first part
         if ($startProc.Contains(" ")) {
            $startProc = $startProc.Split(" ")[0]
         }
      }
      else {
         $startProc = $null
      }

      # check if $status contains "mshta.exe"

      if ($startCmd.Contains("mshta.exe")) {
         $defaultLink = $true
      }
      else {
         $defaultLink = $false
      }

      if ($htaRunBlocked -ne $true) {
         $score -= 7
      }

      if ($defaultLink -eq $true) {
         $score -= 3
      }

      $result = [PSCustomObject]@{
         RunBlocked  = $htaRunBlocked
         OpenWith    = $startProc
         DefaultLink = $defaultLink
      }

      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlCheckWindowsRecallStatusCU {
   <#
    .SYNOPSIS
        Checks if Windows Recall is enabled for the current user.
    .DESCRIPTION
        Windows Recall is a feature for Copilot+ PC's that cretes a timeline of user activity by taking snapshots of the desktop and processing them using AI.

        https://support.microsoft.com/en-us/windows/retrace-your-steps-with-recall-aa03f8a0-a78b-4b3e-b0a1-2eb8ac48701c
        https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis
    .OUTPUTS
         PSCustomObject
         enabled: true if enabled, false if not
    .EXAMPLE
         Get-vlCheckWindowsRecallStatusCU
    #>

   try {
      <#
         0 (Default)	Enable saving Snapshots for Windows.
         1	Disable saving Snapshots for Windows
      #>
      $riskScore = 50

      $value = Get-vlRegValue -Hive "HKCU" -Path "SOFTWARE\Microsoft\Windows\WindowsAI" -Value "DisableAIDataAnalysis" -IncludePolicies $true

      if ($value -and $value -eq 0) {
         $result = [PSCustomObject]@{
            Enabled = $true
         }

         return New-vlResultObject -result $result -score 0 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-WindowsConfigurationCheck {
   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()


   # disabled for now - since we would trigger a lot of false positives
   if ($params.Contains("all") -or $params.Contains("WCHta")) {
      $checkHtaEnabled = Get-CheckHTAEnabled
      $Output += [PSCustomObject]@{
         Name         = "WCHta"
         DisplayName  = "WindowsConfiguration HTA"
         Description  = "This test validates whether HTA (HTML Application) execution is enabled for the current user. HTA files can be used to execute malicious scripts or actions if not properly controlled."
         Score        = $checkHtaEnabled.Score
         ResultData   = $checkHtaEnabled.Result
         RiskScore    = $checkHtaEnabled.RiskScore
         ErrorCode    = $checkHtaEnabled.ErrorCode
         ErrorMessage = $checkHtaEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCCURecallStatus")) {
      $checkWindowsRecallStatus = Get-vlCheckWindowsRecallStatusCU
      $Output += [PSCustomObject]@{
         Name         = "WCCURecallStatus"
         DisplayName  = "WindowsConfiguration Recall status - User"
         Description  = "This test determines the status of Windows Recall, a feature introduced with Windows 11 24H2 that creates a timeline of user activity by capturing desktop screenshots. Attackers could potentially exploit the collected data by extracting sensitive information."
         Score        = $checkWindowsRecallStatus.Score
         ResultData   = $checkWindowsRecallStatus.Result
         RiskScore    = $checkWindowsRecallStatus.RiskScore
         ErrorCode    = $checkWindowsRecallStatus.ErrorCode
         ErrorMessage = $checkWindowsRecallStatus.ErrorMessage
      }
   }

   return $output
}

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


Write-Output (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)
