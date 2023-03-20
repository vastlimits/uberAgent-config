#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force
. $PSScriptRoot\..\Shared\StlParser.ps1 -Force

$authRootCabTemp = "$env:TEMP\uAauthrootstl.cab"
$tempAuthRootStl = "$env:TEMP\uAauthroot.stl"

function Get-vlRootCertificateInstallationCheck {
    <#
    .SYNOPSIS
        Function that checks if current user root certificate installation is enabled.
    .DESCRIPTION
        Function that checks if current user root certificate installation is enabled.
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
        # check if HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots - Flags (REG_DWORD) - 1
        $protectedRoots = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\SystemCertificates\Root" -Value "ProtectedRoots"

        if ($protectedRoots -eq 1) {
            $result = [PSCustomObject]@{
                enabled = $false
            }
            # Root certificate installation is disabled
            return New-vlResultObject -result $result -score 10
        }
        else {
            $result = [PSCustomObject]@{
                enabled = $true
            }
            # Root certificate installation is enabled
            return New-vlResultObject -result $result -score 2
        }
    }
    catch {
        return New-vlErrorObject($_)
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
        #EnableDisallowedCertAutoUpdate
        #RootDirUrl
        # check if 'HKLM:\Software\Policies\Microsoft\SystemCertificates\AuthRoot' -Name DisableRootAutoUpdate is set to 1
        $disableRootAutoUpdate = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -Value "DisableRootAutoUpdate"

        if ($disableRootAutoUpdate -eq 1) {
            $result = [PSCustomObject]@{
                enabled = $false
            }
            # Updates are disabled
            return New-vlResultObject -result $result  -score 2
        }
        else {
            $result = [PSCustomObject]@{
                enabled = $true
            }
            # Updates are enabled
            return New-vlResultObject -result $result -score 10
        }
    }
    catch {
        return New-vlErrorObject($_)
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
        $certs = Get-ChildItem cert:\ -Recurse
        $expCets = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and $_.NotAfter -lt (Get-Date) } | Select-Object -Property FriendlyName, Issuer, NotAfter, Thumbprint
        $willExpire30 = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and ($_.NotAfter -gt (Get-Date) -and $_.NotAfter -lt (Get-Date).AddDays(30)) } | Select-Object -Property FriendlyName, Issuer, NotAfter, Thumbprint
        $willExpire60 = $certs | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and ($_.NotAfter -gt (Get-Date).AddDays(30) -and $_.NotAfter -lt (Get-Date).AddDays(60)) } | Select-Object -Property FriendlyName, Issuer, NotAfter, Thumbprint
    
        $result = [PSCustomObject]@{
            expired      = $expCets
            willExpire30 = $willExpire30
            willExpire60 = $willExpire60
        }
        # Updates are enabled
        return New-vlResultObject -result $result -score 10
    }
    catch {
        return New-vlErrorObject($_)
    }
}

function Remove-vlRemoteAuthRoot {

    <#
    .SYNOPSIS
        Function that removes the AuthRoot.stl file from the %temp% folder.
    .DESCRIPTION
        Function that removes the AuthRoot.stl file from the %temp% folder.
    .EXAMPLE
        Remove-vlRemoteAuthRoot
    #>

    try {
        #check if $authRootCabTemp already exists
        if (Test-Path $authRootCabTemp) {
            Remove-Item $authRootCabTemp
        }

        #check if $tempAuthRootStl already exists
        if (Test-Path $tempAuthRootStl) {
            Remove-Item $tempAuthRootStl
        }
    }
    catch {
        return New-vlErrorObject($_)
    }
}

function Get-vlRemoteAuthRoot {
    <#
    .SYNOPSIS
        Function downloads the latest AuthRoot.stl file from Microsoft and saves it to the %temp% folder.
    .DESCRIPTION
        Function downloads the latest AuthRoot.stl file from Microsoft and saves it to the %temp% folder.
    .OUTPUTS
        Returns the path to the downloaded AuthRoot.stl file.
        If there returns an empty string.
    .EXAMPLE
        Get-vlRemoteAuthRoot
    #>

    try {
        #Download the latest AuthRoot.stl file from Microsoft and save it to the %temp% folder
        #http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab

        #alternativ: http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab
        $authRootCabUrl = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"

        # Cleanup
        Remove-vlRemoteAuthRoot

        # Download the CAB file
        Invoke-WebRequest -Uri $authRootCabUrl -OutFile $authRootCabTemp -UseBasicParsing

        #Expand the CAB file
        Expand-vlCabFile -CabFilePath $authRootCabTemp -DestinationFilePath $tempAuthRootStl       

        #check if $tempAuthRootStl was created
        if (Test-Path $tempAuthRootStl) {
            return $tempAuthRootStl
        }

        return ""
    }
    catch {
        return ""
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
        Get-vlLastCTLSyncTime
    #>
    
    # Parameter Value
    [CmdletBinding()]
    param (
        $syncKey
    )

    try {
        #Get the last time the AuthRoot.stl file was synced
        $lastSyncTimeBytes = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate" -Value $syncKey

        #check if $lastSyncTimeBytes is a byte array and has a length of 8
        if ($lastSyncTimeBytes.Length -eq 8) {
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

function Get-vlStlFromRegistryToFile {
    <#
    .SYNOPSIS
        Function that gets the AuthRoot.stl file from the registry.
    .DESCRIPTION
        Function that gets the AuthRoot.stl file from the registry.
    .OUTPUTS
        Returns the path to the AuthRoot.stl file.
        If there returns an empty string.
    .EXAMPLE
        Get-vlStlFromRegistry
    #>

    try {
        $tempAuthRootStl = "$env:TEMP\uAauthroot-local.stl"

        #Get the AuthRoot.stl file from the registry
        $authRootStl = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate" -Value "EncodedCtl"

        #check if $authRootStl is not empty
        if ($authRootStl.Length -gt 0) {
            #check if $tempAuthRootStl already exists
            if (Test-Path $tempAuthRootStl) {
                Remove-Item $tempAuthRootStl
            }

            #Save the AuthRoot.stl file to the %temp% folder
            [System.IO.File]::WriteAllBytes($tempAuthRootStl, $authRootStl)

            return $tempAuthRootStl
        }

        return ""
    }
    catch {
        return ""
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
        Get-vlStlFromRegistry
    #>

    try {
        #Get the AuthRoot.stl file from the registry
        $authRootStl = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate" -Value "EncodedCtl"

        #check if $authRootStl is not empty
        if ($authRootStl.Length -gt 0) {
            return $authRootStl
        }

        return ""
    }
    catch {
        return ""
    }
}

function Get-vlCompareFiles($file1, $file2) {
    <#
    .SYNOPSIS
        Function that compares two files.
    .DESCRIPTION
        Function that compares two files.
    .OUTPUTS
        Returns true if the files are the same.
        Returns false if the files are not the same.
    .EXAMPLE
        Get-vlCompareFiles -file1 "C:\temp\file1.txt" -file2 "C:\temp\file2.txt"
    #>

    try {
        #check if $file1 and $file2 are not empty
        if ($file1 -and $file2) {
            #check if $file1 and $file2 exist
            if ((Test-Path $file1) -and (Test-Path $file2)) {
                #check if $file1 and $file2 are the same
                $hash1 = (Get-FileHash $file1 -Algorithm SHA256).Hash
                $hash2 = (Get-FileHash $file2 -Algorithm SHA256).Hash
                if ($hash1 -eq $hash2 ) {
                    return $true
                }
            }
        }

        return $false
    }
    catch {
        return $false
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
        Get-vlCompareList -trustList @("cert1", "cert2") -certList @("cert1", "cert2")
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
    # Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.Issuer -eq $_.Subject }
    # Get-ChildItem -Path cert:\CurrentUser\My | Where-Object { $_.Issuer -eq $_.Subject }
    # Get-ChildItem -Path cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject }
    # Get-ChildItem -Path cert:\CurrentUser\Root | Where-Object { $_.Issuer -eq $_.Subject }
    #>

    #last time the AuthRoot.stl file was synced
    try {
        $score = 10

        #Load Stl
        $localAuthRootStl = Get-vlStlFromRegistryToMemory #Get-vlStlFromRegistry

        #add all certificates that are not expired from the current user
        $currentUserCerts = (Get-ChildItem cert:\CurrentUser\Root | Where-Object { $_.NotAfter -ge (Get-Date) }) | Select-Object -Property Thumbprint, Issuer, Subject, NotAfter, NotBefore

        #get all certificates that are not expired from the local machine
        $localMachineCerts = (Get-ChildItem cert:\LocalMachine\Root | Where-Object { $_.NotAfter -ge (Get-Date) }) | Select-Object -Property Thumbprint, Issuer, Subject, NotAfter, NotBefore

        #extract CTL
        $trustedCertList = Get-vlCertificateTrustListFromBytes -bytes $localAuthRootStl
        
        # Create the result object
        $result = [PSCustomObject]@{
            CurrentUser  = (Get-vlCompareCertTrustList -trustList $trustedCertList -certList $currentUserCerts).UnknownCerts
            LocalMachine = (Get-vlCompareCertTrustList -trustList $trustedCertList -certList $localMachineCerts).UnknownCerts
        }

        return New-vlResultObject -result $result -score $score -riskScore 50
    }
    catch {
        return New-vlErrorObject -context $_
    }

}

function Get-vlTimeScore($time) {
    <#
    .SYNOPSIS
        Function that calculates the last sync score based on the time.
    .DESCRIPTION
        Function that calculates the last sync score based on the time.
    .OUTPUTS
        Returns the score based on the time.
    .EXAMPLE
        Get-vlTimeScore
    #>

    if ($null -eq $time) {
        return -3
    }

    #check if time is less than 14 days
    if ($time -lt (Get-Date).AddDays(-14)) {
        return -3
    }

    #check if time is less than 7 days
    if ($time -lt (Get-Date).AddDays(-7)) {
        return -2
    }

    #check if time is less than 2 days
    if ($time -lt (Get-Date).AddDays(-2)) {
        return -1
    }


    return 0
}

function Get-vlCheckSyncTimes {
    <#
    .SYNOPSIS
        Function that checks when the Certificates were last synced.
    .DESCRIPTION
        Function that checks when the Certificates were last synced.
    .OUTPUTS
        Returns the last time the AuthRoot.stl file was synced.
    .EXAMPLE
        Get-vlCompareList -trustList @("cert1", "cert2") -certList @("cert1", "cert2")
    #>

    $score = 10
    $riskScore = 50
    
    try {
        $lastCTLSyncTime = Get-vlLastGetSyncTimeByKey -syncKey "LastSyncTime" # Gets the last time the AuthRoot.stl file was synced
        $lastCRLSyncTime = Get-vlLastGetSyncTimeByKey -syncKey "DisallowedCertLastSyncTime" # Gets the last time the CRL file was synced
        $lastPRLSyncTime = Get-vlLastGetSyncTimeByKey -syncKey "PinRulesLastSyncTime" # Gets the last time the PinRules file was synced


        # worse score would be 1 if all 3 are not synced in the last 14 days
        $score += Get-vlTimeScore -time $lastCTLSyncTime
        $score += Get-vlTimeScore -time $lastCRLSyncTime

        # on windows 7 there is no PRL
        if( (Get-vlIsWindows7) -eq $false) {
            $score += Get-vlTimeScore -time $lastPRLSyncTime
        }
        
        # Create the result object
        $result = [PSCustomObject]@{
            CTL = $lastCTLSyncTime
            CRL = $lastCRLSyncTime
            PRL = $lastPRLSyncTime
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
        Function that performs the Certificate check and returns the result to the uberAgent.
    .DESCRIPTION
        Function that performs the Certificate check and returns the result to the uberAgent.
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

    if ($params.Contains("all") -or $params.Contains("protectedRoots")) {
        $protectedRoots = Get-vlRootCertificateInstallationCheck    
        $Output += [PSCustomObject]@{
            Name         = "Certificate - protectedRoots"
            Score        = $protectedRoots.Score
            ResultData   = $protectedRoots.Result
            RiskScore    = 80
            ErrorCode    = $protectedRoots.ErrorCode
            ErrorMessage = $protectedRoots.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("expiredCerts")) {
        $protectedRoots = Get-vlExpiredCertificateCheck    
        $Output += [PSCustomObject]@{
            Name         = "Certificate - expiredCerts"
            Score        = $protectedRoots.Score
            ResultData   = $protectedRoots.Result
            RiskScore    = 20
            ErrorCode    = $protectedRoots.ErrorCode
            ErrorMessage = $protectedRoots.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("autoCertUpdate")) {
        $autoCertUpdateCheck = Get-vlAutoCertificateUpdateCheck  
        $Output += [PSCustomObject]@{
            Name         = "Certificate - autoCertUpdate"
            Score        = $autoCertUpdateCheck.Score
            ResultData   = $autoCertUpdateCheck.Result
            RiskScore    = 80
            ErrorCode    = $autoCertUpdateCheck.ErrorCode
            ErrorMessage = $autoCertUpdateCheck.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("lastSync")) {
        $lastSync = Get-vlCheckSyncTimes
        $Output += [PSCustomObject]@{
            Name         = "Certificate - lastSync"
            Score        = $lastSync.Score
            ResultData   = $lastSync.Result
            RiskScore    = $lastSync.RiskScore
            ErrorCode    = $lastSync.ErrorCode
            ErrorMessage = $lastSync.ErrorMessage
        }
    }
    if ($params.Contains("all") -or $params.Contains("trustedByWindows")) {
        $ctlCheck = Get-vlGetCTLCheck
        $Output += [PSCustomObject]@{
            Name         = "Certificate - trustedByWindows"
            Score        = $ctlCheck.Score
            ResultData   = $ctlCheck.Result
            RiskScore    = $ctlCheck.RiskScore
            ErrorCode    = $ctlCheck.ErrorCode
            ErrorMessage = $ctlCheck.ErrorMessage
        }
    }
    
    return $output
}

Write-Output (Get-vlCertificateCheck | ConvertTo-Json -Compress)