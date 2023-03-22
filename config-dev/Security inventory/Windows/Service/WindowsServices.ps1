. $PSScriptRoot\..\Shared\Helper.ps1 -Force

function Get-vlServiceLocations {
   <#
   .SYNOPSIS
       Checks whether services are located outside common locations
   .DESCRIPTION
       Checks whether services are located outside common locations
   .LINK

   .NOTES

   .OUTPUTS
       A [psobject] containing services located outside common locations. Empty if nothing was found.
   .EXAMPLE
       Get-vlServiceLocations
   #>

   param (

   )

   process {
       try {
            $ServiceArray = @()
            Get-vlRegSubkeys2 -Hive HKLM -Path 'SYSTEM\CurrentControlSet\Services' | Where-Object {$_.ImagePath} | ForEach-Object -process {
               $ImagePath = $PSItem.ImagePath
               if ($ImagePath -inotmatch '^(\\\?\?\\)?\\?SystemRoot.*$|^(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\WINDOWS\\(system32|syswow64|servicing).*$|^(\\\?\?\\)?"?C:\\Program Files( \(x86\))?\\.*$|^(\\\?\?\\)?"?C:\\WINDOWS\\Microsoft\.NET\\.*$|^(\\\?\?\\)?"?C:\\ProgramData\\Microsoft\\Windows Defender\\.*$') {
                  $ServiceArray += $ImagePath
               }

            }

            if ($ServiceArray.Count -eq 0)
            {
               $result = [PSCustomObject]@{
                  Services = ""
               }
               # No services outside common locations found
               return New-vlResultObject -result $result -score 10
            }
            else 
            {
               $result = [PSCustomObject]@{
                  Services = $ServiceArray
               }
               # Services outside common location found
               return New-vlResultObject -result $result -score 1
            }
       }
       catch {

           return New-vlErrorObject($_)
       }
       finally {

       }

   }
   
}

function Get-vlServiceDLLLocations {
    <#
    .SYNOPSIS
        Checks whether service.dll files are located outside common locations
    .DESCRIPTION
        Checks whether service.dll files are located outside common locations
    .LINK
 
    .NOTES
 
    .OUTPUTS
        A [psobject] containing services with service.dll files located outside common locations. Empty if nothing was found.
    .EXAMPLE
        Get-vlServiceDLLLocations
    #>
 
    param (
 
    )
 
    process {
        try {
             $ServiceArray = @()
             $ServiceDLLArray = @()
             Get-ItemProperty hklm:\SYSTEM\CurrentControlSet\Services\*\Parameters | Where-Object { $_.servicedll } | ForEach-Object -process {
 
                $ServiceDLL = $PSItem.ServiceDLL
                $ServiceName = ($PSItem.PSParentPath).split('\\')[-1]
                if ($ServiceDLL -inotmatch '^C:\\WINDOWS\\system32.*$') {
                   
                   $ServiceArray += $ServiceName
                   $ServiceDLLArray += $ServiceDLL
                }
 
             }
 
             if ($ServiceArray.Count -eq 0)
             {
                $result = [PSCustomObject]@{
                   Services = ""
                   ServiceDLLs = ""
                }
                # No service.dll file outside common locations found
                return New-vlResultObject -result $result -score 10
             }
             else 
             {
                $result = [PSCustomObject]@{
                   Services = $ServiceArray
                   ServiceDLLs = $ServiceDLLArray
                }
                # Service.dll file outside common location found
                return New-vlResultObject -result $result -score 1
             }
        }
        catch {
 
            return New-vlErrorObject($_)
        }
        finally {
 
        }
 
    }
    
 }


function Get-vlWindowsServicesCheck {
   <#
   .SYNOPSIS
       Function that performs the Windows services check and returns the result to the uberAgent.
   .DESCRIPTION
       Function that performs the Windows services check and returns the result to the uberAgent.
   .NOTES
       The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
       Specific tests can be called by passing the test name as a parameter to the script args.
       Passing no parameters or -all to the script will run all tests.
   .LINK
       https://uberagent.com
   .OUTPUTS
       A list with vlResultObject | vlErrorObject [psobject] containing the test results
   .EXAMPLE
       Get-vlWindowsServicesCheck
   #>

   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()

   if ($params.Contains("all") -or $params.Contains("ServiceLocations")) {
       $ServiceLocations = Get-vlServiceLocations    
       $Output += [PSCustomObject]@{
           Name         = "Locations"
           DisplayName  = "Uncommon locations"
           Description  = "Checks whether services are running in uncommon locations"
           Score        = $ServiceLocations.Score
           ResultData   = $ServiceLocations.Result
           RiskScore    = 100
           ErrorCode    = $ServiceLocations.ErrorCode
           ErrorMessage = $ServiceLocations.ErrorMessage
       }
   }

   if ($params.Contains("all") -or $params.Contains("ServiceDLLLocations")) {
    $ServiceDLLLocations = Get-vlServiceDLLLocations    
    $Output += [PSCustomObject]@{
        Name         = "Service.dll"
        DisplayName  = "Uncommon locations of service.dll"
        Description  = "Checks whether services use service.dll in uncommon locations"
        Score        = $ServiceDLLLocations.Score
        ResultData   = $ServiceDLLLocations.Result
        RiskScore    = 90
        ErrorCode    = $ServiceDLLLocations.ErrorCode
        ErrorMessage = $ServiceDLLLocations.ErrorMessage
    }
}

   return $output
}

Write-Output (Get-vlWindowsServicesCheck | ConvertTo-Json -Compress)

