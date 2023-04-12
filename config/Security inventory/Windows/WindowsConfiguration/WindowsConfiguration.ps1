
. $PSScriptRoot\..\Shared\Helper.ps1 -Force


function Get-vlDefaultProgramForExtension {
   <#
    .SYNOPSIS
        Gets the default program for a specific file extension
    .DESCRIPTION
        Gets the default program for a specific file extension
    .OUTPUTS
        A [string] containing the path to the default program
    .EXAMPLE
        Get-vlDefaultProgramForExtension
    #>

   param (
      [Parameter(Mandatory = $true)]
      [string]$Extension
   )

   $progId = Get-vlRegValue -Hive "HKCR" -Path "\$Extension"
   if ($progId -ne $null) {
      $command1 = (Get-vlRegValue -Hive "HKCR" -Path "\$progId\shell\open\command")
      $command2 = (Get-vlRegValue -Hive "HKCR" -Path "\$progId\shell\printto\command")

      # select the one that is not null
      $command = if ($command1 -ne $null -and $command1 -ne "") { $command1 } else { $command2 }

      if ($command -ne $null) {
         return $command
      }
      else {
         Write-Debug "No 'open' command found for program ID $progId."
      }
   }
   else {
      Write-Debug "No default program found for extension $Extension."
   }
}

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

      #$htaExecuteStatus = Run-vlHtaCode $htacode
      $htaRunBlocked = Test-vlBlockedProgram -ProgramPath "mshta.exe"

      $defaultLink = $true
      $startCmd = (Get-vlDefaultProgramForExtension -Extension ".hta").ToLower()

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

      # check if $status starts with "${env:SystemRoot}" and contains "mshta.exe"
      $winDir = ("${env:SystemRoot}").ToLower()

      if ($startCmd.StartsWith($winDir) -and $startCmd.Contains("mshta.exe")) {
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

function Get-BitlockerEnabled {
   <#
    .SYNOPSIS
        Checks if Bitlocker is enabled and used on the system.
    .DESCRIPTION
        Checks if Bitlocker is enabled and used on the system.
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-BitlockerEnabled
    #>

   try {
      $score = 10

      #check if bitlocker is enabled using Get-BitLockerVolume
      $bitlockerEnabled = Get-BitLockerVolume | Select-Object -Property MountPoint, ProtectionStatus, EncryptionMethod, EncryptionPercentage

      if ($bitlockerEnabled) {
         $bitlockerEnabled = Convert-vlEnumToString $bitlockerEnabled
      }

      if ($bitlockerEnabled.ProtectionStatus -ne "On") {
         $score = 0
      }
      else {
         if ($bitlockerEnabled.EncryptionPercentage -eq 100) {
            $score = 10
         }
         else {
            $score = 5
         }
      }

      return New-vlResultObject -result $bitlockerEnabled -score $score
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-COMHijacking {
   <#
    .SYNOPSIS
        Checks if mmc.exe is hijacked
    .DESCRIPTION
        Checks if mmc.exe is hijacked
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-COMHijacking
    #>
   try {

      $expectedValue = "$($env:SystemRoot)\system32\mmc.exe ""%1"" %*"

      $value = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Classes\mscfile\shell\open\command"

      if (($value.ToLower()) -eq ($expectedValue.ToLower())) {
         $result = [PSCustomObject]@{
            Detected = $false
         }

         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Detected = $true
         }
         return New-vlResultObject -result $result -score 0
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlTimeProviderHijacking {
   <#
    .SYNOPSIS
        Checks if w32time.dll is hijacked
    .DESCRIPTION
        Checks if w32time.dll is hijacked
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-vlTimeProviderHijacking
    #>

   try {
      $expectedValue = "$($env:SystemRoot)\system32\w32time.dll"

      $value = Get-vlRegValue -Hive "HKLM" -Path "SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer" -Value "DllName"

      if (($value.ToLower()) -eq ($expectedValue.ToLower())) {
         $result = [PSCustomObject]@{
            Detected = $false
         }

         return New-vlResultObject -result $result -score 10
      }
      else {
         $result = [PSCustomObject]@{
            Detected = $true
         }
         return New-vlResultObject -result $result -score 0
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlWindowsPersistanceCheck {
   <#
    .SYNOPSIS
        Runs sfc /verifyonly and checks if CBS.log contains "corrupt" or "repaired"
    .DESCRIPTION
        Runs sfc /verifyonly and checks if CBS.log contains "corrupt" or "repaired"
    .OUTPUTS
        PSCustomObject
        detected: true if detected, false if not
    .EXAMPLE
        Get-vlWindowsPersistanceCheck
    #>

   try {
      $log_file = "$($env:SystemRoot)\Logs\CBS\CBS.log"

      #run sfc /verifyonly and wait for it to finish run it hidden
      #$sfc = Start-Process -FilePath "sfc.exe" -ArgumentList "/verifyonly" -Wait -WindowStyle Hidden

      $today = (Get-Date).ToString("yyyy-MM-dd")

      # Check whether the log file exists
      if (Test-Path $log_file) {
         # Read the log file line by line and filter the lines that start with today's date
         $todayEntries = Get-Content $log_file | Where-Object { $_.StartsWith($today) }

         # Extract the numbers of the SR entries
         $numbers = $todayEntries | Where-Object { $_ -match "\[SR\]" } | ForEach-Object { if ($_ -match "(\b0*[0-9]{1,8}\b)\s+\[SR\]") { $matches[1] } }

         # Find the smallest and the largest SR entry
         $smallest = $numbers | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum
         $largest = $numbers | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum

         # Filter the lines that are between the smallest and the largest SR entry
         $filteredEntries = $todayEntries | Where-Object {
            if ($_ -match "(\d{1,8})\s+\[SR\]") {
               $number = $matches[1]
               $number -ge $smallest -and $number -le $largest
            }
         }

         # Output the filtered lines
         $filteredEntries
      }
      else {
         # Throw error if the log file does not exist
         throw "Log file does not exist"
      }

      #read the log file and check if it contains "corrupt" or "repaired"
      $defect = Get-Content $log_file | Select-String -Pattern "(corrupt|repaired)"

      if ($defect) {
         $result = [PSCustomObject]@{
            Detected = $true
         }
         return New-vlResultObject -result $result -score 0
      }
      else {
         $result = [PSCustomObject]@{
            Detected = $false
         }
         return New-vlResultObject -result $result -score 10
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


   if ($params.Contains("all") -or $params.Contains("WCHta")) {
      $checkHtaEnabled = Get-CheckHTAEnabled
      $Output += [PSCustomObject]@{
         Name         = "WCHta"
         DisplayName  = "WindowsConfiguration HTA"
         Description  = "Checks if HTA execution is enabled on the system."
         Score        = $checkHtaEnabled.Score
         ResultData   = $checkHtaEnabled.Result
         RiskScore    = 80
         ErrorCode    = $checkHtaEnabled.ErrorCode
         ErrorMessage = $checkHtaEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCBitlocker")) {
      $checkBitlockerEnabled = Get-BitlockerEnabled
      $Output += [PSCustomObject]@{
         Name         = "WCBitlocker"
         DisplayName  = "WindowsConfiguration Bitlocker"
         Description  = "Checks if Bitlocker is enabled on the system."
         Score        = $checkBitlockerEnabled.Score
         ResultData   = $checkBitlockerEnabled.Result
         RiskScore    = 80
         ErrorCode    = $checkBitlockerEnabled.ErrorCode
         ErrorMessage = $checkBitlockerEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCComHijacking")) {
      $COMHijacking = Get-COMHijacking
      $Output += [PSCustomObject]@{
         Name         = "WCComHijacking"
         DisplayName  = "WindowsConfiguration COM hijacking"
         Description  = "Checks if COM is hijacked."
         Score        = $COMHijacking.Score
         ResultData   = $COMHijacking.Result
         RiskScore    = 80
         ErrorCode    = $COMHijacking.ErrorCode
         ErrorMessage = $COMHijacking.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCTimeProvHijacking")) {
      $timeProviderHijacking = Get-vlTimeProviderHijacking
      $Output += [PSCustomObject]@{
         Name         = "WCTimeProvHijacking"
         DisplayName  = "WindowsConfiguration time provider hijacking"
         Description  = "Checks if the time provider is hijacked."
         Score        = $timeProviderHijacking.Score
         ResultData   = $timeProviderHijacking.Result
         RiskScore    = 80
         ErrorCode    = $timeProviderHijacking.ErrorCode
         ErrorMessage = $timeProviderHijacking.ErrorMessage
      }
   }

   <#
    #TODO: Add a better logic to check for "corrupt" or "repaired" in CBS.log
    if ($params.Contains("all") -or $params.Contains("persistancecheck")) {
        $persistancecheck = Get-vlWindowsPersistanceCheck
        $Output += [PSCustomObject]@{
            Name         = "WindowsConfiguration - persistancecheck"
            Score        = $persistancecheck.Score
            ResultData   = $persistancecheck.Result
            RiskScore    = 80
            ErrorCode    = $persistancecheck.ErrorCode
            ErrorMessage = $persistancecheck.ErrorMessage
        }
    }
    #>

   return $output
}

Write-Host (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)
# SIG # Begin signature block
# MIIFyAYJKoZIhvcNAQcCoIIFuTCCBbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAy1oA7s5DOxSez
# wLg680YEAIXiL87JSeJ0cz8i9pB6caCCAywwggMoMIICEKADAgECAhAV/4qQJS3s
# n0DL41n50ym+MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNVBAMMIVRlc3QgUG93ZXJT
# aGVsbCBDb2RlIFNpZ25pbmcgQ2VydDAeFw0yMzA0MDYwOTA0MjNaFw0yODA0MDYw
# OTE0MjNaMCwxKjAoBgNVBAMMIVRlc3QgUG93ZXJTaGVsbCBDb2RlIFNpZ25pbmcg
# Q2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMY2H9hHui4rAfqN
# n3QDc37qHGDNZBB2g9yFELoJhgKIcvsoEOdjx+1ZqrlSet7j1gBAnOw2hvFmLdLr
# HL5t23Z4FnIBog1ictyCShaUZ4o6YKChLEofvkajnlN/WeEjDWYlmxp8Lp+u/kzc
# SZUUjx+s9IkrlfjDjPXipOzOLPaAzFa+pqqB4gD6czC80aA3h7mx6ot3TT9FMx6k
# 1XCgG2coWpdE+/XGhy99FBgHROskiwUrfO2AG6s2RpppUz2O6kf7ndMj/uDtvSpU
# shDSqMshoLyWnHl4TqarY7roiktIQFFONp3iJ1qKule67xS0xDBuJwhaf62QNKNN
# 67lWU/kCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMDMB0GA1UdDgQWBBRmSIOJwRja8evKIW1LiVBOivpyLTANBgkqhkiG9w0BAQsF
# AAOCAQEAYsHAnLyLgEj87rcgPuGWs51PdU5g9/b2AVdniV0MuljX9Mlw+nnddN6F
# a075DO1/L+dsJdYmxHw9Hp2OdNbqVZCNcI/s3wM+JVTXXkdroPWafJb2caw5V6p3
# p2g32zBdtInxUiL06S/oiUMZg9JK9xu+cTPgFPU2a0xpjx6exNCbYW8ByO8WrT2f
# z3Gh4nSJ9Da3k02F1E3V9jUno4s0fKuYoZDd1MlkNuK5D1A1fH8bsn2J5mR25OHv
# fBBGQIEzbYCXhDPIydtGDvBjj9e3OzMS/h5XcGD5FcyVOwI4/n0A7asKHTbD+JI9
# CT+XeyJVdPVtVbi029LXl5Ztw6SMNjGCAfIwggHuAgEBMEAwLDEqMCgGA1UEAwwh
# VGVzdCBQb3dlclNoZWxsIENvZGUgU2lnbmluZyBDZXJ0AhAV/4qQJS3sn0DL41n5
# 0ym+MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMOTezdpnhURvvR1t49D6XKoDR3SKT2D
# Y7c1niv7aJhcMA0GCSqGSIb3DQEBAQUABIIBAKNourtY72/6wbrbI2xscr5VxoHt
# vgv5OJ7CyPlOCmhMybdbBUWOtXhl+JMKzWcdIPvUEYD9DmHEdl4NwABgeqBSA+Cl
# nRlM5SIrQhL3jDUDHkiLCSPenyUhSxKOqlouyukL89Qq0tRrRKmb1pBWflj0MCJl
# qTyRVzgBaVC9uD4Q8qz6ZiEjJmfnrPEse38UQKuCYZPxhctwiLQmnXh6tKcClpWD
# Wbb+Pk158GlzyoupjzEVc57PaIxCtDWk1m2yqLy00118wRDZjUFbtfmPUxWPpcZ5
# Sa0iOQUSsdZXYy7xjUuM+dIWz5AXuLPEKfOHpAz/NjktSlBIRNtsODafW2o=
# SIG # End signature block
