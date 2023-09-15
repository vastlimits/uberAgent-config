#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force
. $PSScriptRoot\..\Shared\StlParser.ps1 -Force

function Get-vlRootCertificateInstallationCheck {
   <#
    .SYNOPSIS
        Function that checks if a user can install root certificates on the system.
    .DESCRIPTION
        Function that checks if a user can install root certificates on the system.
    .OUTPUTS
        If root certificate installation is enabled, the function returns a PSCustomObject with the following properties:
        enabled: true
        If root certificate installation is disabled, the function returns a PSCustomObject with the following properties:
        enabled: false
    .NOTES
        Ref: https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
    .EXAMPLE
        Get-vlRootCertificateInstallationCheck
    #>

   try {
      <#
        // Set the following flag to inhibit the opening of the CurrentUser's
        // .Default physical store when opening the CurrentUser's "Root" system store.
        // The .Default physical store open's the CurrentUser SystemRegistry "Root"
        // store.
        #define CERT_PROT_ROOT_DISABLE_CURRENT_USER_FLAG    0x1
        // Set the following flag to inhibit the adding of roots from the
        // CurrentUser SystemRegistry "Root" store to the protected root list
        // when the "Root" store is initially protected.
        #define CERT_PROT_ROOT_INHIBIT_ADD_AT_INIT_FLAG     0x2
        #>

      $riskScore = 80

      # check if HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots - Flags (REG_DWORD) - 1
      $protectedRoots = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Value "Flags"

      if ($protectedRoots -eq 1) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # Root certificate installation is disabled
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # Root certificate installation is enabled
         return New-vlResultObject -result $result -score 2 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlAutoCertificateUpdateCheck {
   <#
    .SYNOPSIS
        Function that checks if root certificate auto update is enabled.
    .DESCRIPTION
        Function that checks if root certificate auto update is enabled.
    .OUTPUTS
        If root certificate auto update is enabled, the function returns a PSCustomObject with the following properties:
        enabled: true
        If root certificate auto update is disabled, the function returns a PSCustomObject with the following properties:
        enabled: false
    .NOTES
        Ref: https://woshub.com/updating-trusted-root-certificates-in-windows-10/
    .EXAMPLE
        Get-vlAutoCertificateUpdateCheck
    #>

   try {
      $riskScore = 80

      #EnableDisallowedCertAutoUpdate
      #RootDirUrl
      # check if 'HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot' -Name DisableRootAutoUpdate is set to 1
      $disableRootAutoUpdate = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot" -Value "DisableRootAutoUpdate" -IncludePolicies $true

      if ($disableRootAutoUpdate -eq 1) {
         $result = [PSCustomObject]@{
            Enabled = $false
         }
         # Updates are disabled
         return New-vlResultObject -result $result  -score 2 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            Enabled = $true
         }
         # Updates are enabled
         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlExpiredCertificateCheck {
   <#
    .SYNOPSIS
        Function that checks if certificates are expired or will expire in the next 30 or 60 days.
    .DESCRIPTION
        Function that checks if certificates are expired or will expire in the next 30 or 60 days.
    .OUTPUTS
        If root certificate auto update is enabled, the function returns a PSCustomObject with the following properties:
        expired: List of expired certificates
        willExpire30: List of certificates that will expire in the next 30 days
        willExpire60: List of certificates that will expire in the next 60 days
    .EXAMPLE
        Get-vlExpiredCertificateCheck
    #>

   try {
      $score = 10
      $riskScore = 20

      $certs = Get-ChildItem -Path Cert:\LocalMachine -Recurse -ErrorAction Stop
      $expCets = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and $_.NotAfter -lt (Get-Date) } | Select-Object -Property FriendlyName, Issuer, NotBefore, NotAfter, Thumbprint
      $willExpire30 = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and ($_.NotAfter -gt (Get-Date) -and $_.NotAfter -lt (Get-Date).AddDays(30)) } | Select-Object -Property FriendlyName, Issuer, NotBefore, NotAfter, Thumbprint
      $willExpire60 = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and ($_.NotAfter -gt (Get-Date).AddDays(30) -and $_.NotAfter -lt (Get-Date).AddDays(60)) } | Select-Object -Property FriendlyName, NotBefore, Issuer, NotAfter, Thumbprint


      # convert Date object to ISO timestring
      $expCets = $expCets | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         $_
      }

      $willExpire30 = $willExpire30 | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         $_
      }

      $willExpire60 = $willExpire60 | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         $_
      }

      if ( $willExpire60.Length -gt 0 ) {
         $score = 7
      }

      if ( $willExpire30.Length -gt 0 ) {
         $score = 4
      }

      if ( $expCets.Length -gt 0 ) {
         $score = 0
      }

      $result = [PSCustomObject]@{
         expired      = $expCets
         willExpire30 = $willExpire30
         willExpire60 = $willExpire60
      }
      # Updates are enabled
      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlLastGetSyncTimeByKey {
   <#
    .SYNOPSIS
        Function that gets the last sync time of the given key for SystemCertificates.
    .DESCRIPTION
        Function that gets the last sync time of the given key for SystemCertificates.
    .INPUTS
        $syncKey: The key that should be checked
    .OUTPUTS
        Returns the last sync time of the given key for SystemCertificates.
    .EXAMPLE
        Get-vlLastGetSyncTimeByKey
    #>

   # Parameter Value
   [CmdletBinding()]
   [OutputType([System.DateTime])]
   param (
      $syncKey
   )

   try {
      #Get the last time the AuthRoot.stl file was synced
      $lastSyncTimeBytes = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate" -Value $syncKey

      #check if $lastSyncTimeBytes is a byte array and has a length of 8
      if ($null -ne $lastSyncTimeBytes -and $lastSyncTimeBytes.Length -eq 8) {
         # Convert bytes to datetime
         $fileTime = [System.BitConverter]::ToInt64($lastSyncTimeBytes, 0)
         $lastSyncTime = [System.DateTime]::FromFileTimeUtc($fileTime)

         return $lastSyncTime
      }

      return $null
   }
   catch {
      return $null
   }
}

function Get-vlStlFromRegistryToMemory {
   <#
    .SYNOPSIS
        Function that gets the AuthRoot.stl file from the registry.
    .DESCRIPTION
        Function that gets the AuthRoot.stl file from the registry.
    .OUTPUTS
        Returns the path to the AuthRoot.stl file.
        If there returns an empty string.
    .EXAMPLE
        Get-vlStlFromRegistryToMemory
    #>

   try {
      #Get the AuthRoot.stl file from the registry
      $authRootStl = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate" -Value "EncodedCtl"

      #check if $authRootStl is not empty
      if ($null -ne $authRootStl -and $authRootStl.Length -gt 0) {
         return $authRootStl
      }

      return $null
   }
   catch {
      return $null
   }
}

function Get-vlCompareCertTrustList($trustList, $certList) {
   <#
    .SYNOPSIS
        Function that compares two lists.
    .DESCRIPTION
        Function that compares two lists.
    .OUTPUTS
        Returns true if the lists are the same.
        Returns false if the lists are not the same.
    .EXAMPLE
        Get-vlCompareCertTrustList -trustList @("cert1", "cert2") -certList @("cert1", "cert2")
    #>

   try {
      #check if $trustList and $certList are not empty
      if ($trustList -and $certList) {
         #check if the Thumbprint of the certificate is in the trust list. If yes add to list known certificates else add to unknown certificates
         $unknownCerts = @()
         $knownCerts = @()
         foreach ($cert in $certList) {
            if ($cert.Thumbprint -in $trustList) {
               $knownCerts += $cert
            }
            else {
               $unknownCerts += $cert
            }
         }

         return [PSCustomObject]@{
            KnownCerts   = $knownCerts
            UnknownCerts = $unknownCerts
         }
      }

      return $false
   }
   catch {
      return $false
   }
}

function Get-vlGetCTLCheck {
   <#
    .SYNOPSIS
        Check if there are unknown certificates installed
    .DESCRIPTION
        Check if there are unknown certificates installed
    .OUTPUTS
        Returns the unknown certificates for LocalMachine and CurrentUser
    .EXAMPLE
        Get-vlGetCTLCheck
    #>

   try {
      $score = 10
      $riskScore = 70

      #Load Stl
      $localAuthRootStl = Get-vlStlFromRegistryToMemory #Get-vlStlFromRegistry

      if ($null -eq $localAuthRootStl) {
         throw "Could not load AuthRoot.stl from registry"
      }

      #get all certificates from the local machine
      $localMachineCerts = Get-ChildItem cert:\LocalMachine\Root -ErrorAction Stop | Select-Object -Property Thumbprint, Issuer, Subject, NotAfter, NotBefore

      # convert NotAfter and NotBefore to string iso format
      $localMachineCerts = $localMachineCerts | ForEach-Object {
         $_.NotAfter = Get-vlTimeString -time $_.NotAfter
         $_.NotBefore = Get-vlTimeString -time $_.NotBefore
         return $_
      }

      # define allowList containing thumbprints of certificates that are allowed
      # https://learn.microsoft.com/en-US/troubleshoot/windows-server/identity/trusted-root-certificates-are-required

      $allowList = @(
         "A43489159A520F0D93D032CCAF37E7FE20A8B419" # Microsoft Root Authority
         "BE36A4562FB2EE05DBB3D32323ADF445084ED656" # Thawte Timestamping CA
         "CDD4EEAE6000AC7F40C3802C171E30148030C072" # Microsoft Root Certificate Authority
         "245C97DF7514E7CF2DF8BE72AE957B9E04741E85" # Copyright (c) 1997 Microsoft Corp.
         "7F88CD7223F3C813818C994614A89C99FA3B5247" # Microsoft Authenticode(tm) Root Authority
         "18F7C1FCC3090203FD5BAA2F861A754976C8DD25" # NO LIABILITY ACCEPTED, (c)97 VeriSign, Inc.
      )

      # filter out $allowList from $localMachineCerts
      $localMachineCerts = $localMachineCerts | Where-Object { $_.Thumbprint -notin $allowList }

      #extract CTL
      $trustedCertList = Get-vlCertificateTrustListFromBytes -bytes $localAuthRootStl -ErrorAction Stop

      # Create the result object
      $UnknownCertificates = (Get-vlCompareCertTrustList -trustList $trustedCertList -certList $localMachineCerts).UnknownCerts

      if ($null -ne $UnknownCertificates -and $UnknownCertificates.Count -gt 0) {
         $score -= 5
      }
      else {
         $UnknownCertificates = @()
      }

      return New-vlResultObject -result $UnknownCertificates -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }

}

function Get-vlCheckSyncTime {
   <#
    .SYNOPSIS
        Function that checks when the Certificates were last synced.
    .DESCRIPTION
        Function that checks when the Certificates were last synced.
    .OUTPUTS
        Returns the last time the AuthRoot.stl file was synced.
    .EXAMPLE
        Get-vlCheckSyncTime
    #>

   $score = 10
   $riskScore = 50

   try {
      $OSVersion = Get-vlOsVersion -ErrorAction Stop

      $lastCTLSyncTime = Get-vlLastGetSyncTimeByKey -syncKey "LastSyncTime" # Gets the last time the AuthRoot.stl file was synced
      $lastCRLSyncTime = Get-vlLastGetSyncTimeByKey -syncKey "DisallowedCertLastSyncTime" # Gets the last time the CRL file was synced
      $lastPRLSyncTime = Get-vlLastGetSyncTimeByKey -syncKey "PinRulesLastSyncTime" # Gets the last time the PinRules file was synced


      # worsed score would be 1 if all 3 are not synced in the last 14 days
      $score += Get-vlTimeScore -time $lastCTLSyncTime
      $score += Get-vlTimeScore -time $lastCRLSyncTime

      # Create the result object
      $result = [PSCustomObject]@{
         CTL = Get-vlTimeString -time $lastCTLSyncTime
         CRL = Get-vlTimeString -time $lastCRLSyncTime
      }

      # PRL is available starting with Windows 10
      if ([version]$OSVersion -ge [version]'10.0') {
         $score += Get-vlTimeScore -time $lastPRLSyncTime
         $result | Add-Member -Type NoteProperty -Name "PRL" -Value (Get-vlTimeString -time $lastPRLSyncTime) -ErrorAction Stop
      }

      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlCertificateCheck {
   <#
    .SYNOPSIS
        Function that performs the Certificate check and returns the result to uberAgent.
    .DESCRIPTION
        Function that performs the Certificate check and returns the result to uberAgent.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlCertificateCheck
    #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("CMProtRoot")) {
      $protectedRoots = Get-vlRootCertificateInstallationCheck
      $Output += [PSCustomObject]@{
         Name         = "CMProtRoot"
         DisplayName  = "Protected root certificates"
         Description  = "Checks if root certificates can be installed by users."
         Score        = $protectedRoots.Score
         ResultData   = $protectedRoots.Result
         RiskScore    = $protectedRoots.RiskScore
         ErrorCode    = $protectedRoots.ErrorCode
         ErrorMessage = $protectedRoots.ErrorMessage
      }
   }
   <# disabled for now since there is no real security impact if the certificate is expired
   if ($params.Contains("all") -or $params.Contains("CMExpCerts")) {
      $protectedRoots = Get-vlExpiredCertificateCheck
      $Output += [PSCustomObject]@{
         Name         = "CMExpCerts"
         DisplayName  = "Expired certificates"
         Description  = "Checks if there are expired certificates installed."
         Score        = $protectedRoots.Score
         ResultData   = $protectedRoots.Result
         RiskScore    = $protectedRoots.RiskScore
         ErrorCode    = $protectedRoots.ErrorCode
         ErrorMessage = $protectedRoots.ErrorMessage
      }
   }
   #>
   if ($params.Contains("all") -or $params.Contains("CMAuCerUp")) {
      $autoCertUpdateCheck = Get-vlAutoCertificateUpdateCheck
      $Output += [PSCustomObject]@{
         Name         = "CMAuCerUp"
         DisplayName  = "Auto certificate update"
         Description  = "This test verifies that automatic certificate updating is enabled on the system. When automatic certificate updating is enabled, the system obtains the latest Certificate Revocation List (CRL) and Certificate Trust List (CTL) from the Microsoft Update server. Regularly updating and validating certificates with the latest trust and revocation information is essential to ensure certificate integrity."
         Score        = $autoCertUpdateCheck.Score
         ResultData   = $autoCertUpdateCheck.Result
         RiskScore    = $autoCertUpdateCheck.RiskScore
         ErrorCode    = $autoCertUpdateCheck.ErrorCode
         ErrorMessage = $autoCertUpdateCheck.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("CMLaSync")) {
      $lastSync = Get-vlCheckSyncTime
      $Output += [PSCustomObject]@{
         Name         = "CMLaSync"
         DisplayName  = "Certificate last sync"
         Description  = "This test determines the last time the Certificate Revocation List (CRL) and Certificate Trust List (CTL) were synchronized with Microsoft servers. It also checks the status of enterprise certificate pinning on Windows 10 and above, and the result shows the timestamp of the last update of the PinRules List (PRL)."
         Score        = $lastSync.Score
         ResultData   = $lastSync.Result
         RiskScore    = $lastSync.RiskScore
         ErrorCode    = $lastSync.ErrorCode
         ErrorMessage = $lastSync.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("CMTrByWin")) {
      $ctlCheck = Get-vlGetCTLCheck
      $Output += [PSCustomObject]@{
         Name         = "CMTrByWin"
         DisplayName  = "Certificates trusted by Windows - Machine"
         Description  = "This test relies on the Microsoft maintained Certificate Trust List (CTL) to validate the status of certificates found in the machine's trusted root certificate store. Any certificate that is not recognized or included in the trusted list is flagged as an unknown certificate."
         Score        = $ctlCheck.Score
         ResultData   = $ctlCheck.Result
         RiskScore    = $ctlCheck.RiskScore
         ErrorCode    = $ctlCheck.ErrorCode
         ErrorMessage = $ctlCheck.ErrorMessage
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


Write-Output (Get-vlCertificateCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIRVgYJKoZIhvcNAQcCoIIRRzCCEUMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDf3a+aasjY+cMe
# 12b3mwUnt5IRC5N2whhApqas2rlNJqCCDW0wggZyMIIEWqADAgECAghkM1HTxzif
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
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgtUMUDTYFSZDu
# bZ3pmcJtDOdb6GvAqZyt1NWq1H6VWuQwDQYJKoZIhvcNAQEBBQAEggIAmK/TtJUM
# LhEYWtMqqhZm56a+oDccIbk0UkhQCrOOzxOM1EIkznUTC/jV8+Yu6atJN+3J9f5G
# E9j4cUUgH9yiT1+oNi9vt+zIDFhzo8zXzuILk4TXdf8iQewKpXwoFZxepY/zrADF
# F8l6yU0KPVMKShjjrROH6YbjAQ+LHm0Gi9HTmmTRriwG0EXrmbuGsgMy+DniaCxF
# C7QKsriXCbspsZHpxtxP/zZ5WjJvMUDhOtrgeBmSB577OQDVfLiAw9hr7hZGsuCJ
# pkJp0qbH+Aj5Z1xD9jtkfQxKMe06RiD+bDjm7BJNd2xciauNxyOoSvF9pC2vGhf4
# ht08ZHyfzg2sHvBKIwiFEM+Qi6OsvLtwD5ap0isIVIZ8TNe5Nl7UIzhiCQJwip+M
# 64N0+x081kjh0aOIOagvc8qqV6VKKtbIYQAiVC1BFDbh9uRhee8x+40MVirb2LhN
# VXDf5dzaIPIjIurx3cn3GZZ/ppvmm4cyLDaKguPMESwHf3rHeP+/8u0vowqGJk77
# P+cqBcvT7YNDGA+gHt4DNg91w6PlSPpzZslOf35C0YZ14a2aZ5TCXUGg0A/Z5Ibs
# nfK+lJzykFdXsP/42w1u5TGuuIMElXQMpJ3Xubv9eoNIi4jf4j2RHP5yMOdCj0CY
# ZGA2pK+Go/6YCl8O0wvUr/OLqFMJZwTJZU4=
# SIG # End signature block
