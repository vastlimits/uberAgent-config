# This file should help you to get started with writing SCI tests for Windows.

### Requires elevated privileges? Then add the following line to the top of the script
# #Requires -RunAsAdministrator

### We support PowerShell 3.0 and later, so we need to add the following line to the top of the script
#Requires -Version 3.0

# Include helper functions, like retrun handling, error handling, some registry magic etc.
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#
# To ensure that data is displayed accurately in the Securty Score Splunk dashboard, it's important to follow certain best practices.
#
# 1)  A key practice is to aggregate related values within a test and return the result as a single object.
#     This approach simplifies the analysis and visualization of data, especially when examining related metrics or statuses.
#
#     This allows you to handle dependencies, such as only getting the SSID and encryption method when WIFI is enabled and connected.
#     If you separated these values into separate tests (WIFI enabled, current SSID, encryption method), it would be more difficult to calculate the risk score and merge the data.
#
#     Example: Get-vlGroupSimilarValues.
#
# 2)  Splunk has a default limit of 10,000 characters for a single event; data is truncated if it exceeds this limit.
#     If you expect a result to exceed this limit, consider breaking it into smaller, more manageable pieces.
#
# 3)  The Securty Score Splunk dashboard currently does not support every json structure.
#
#     Example: Get-vlSupportMatrixExample.
#

function Get-vlSimpleExample() {
   <#
   .SYNOPSIS
       This test returns a simple result.
   .DESCRIPTION
         This test returns a simple result.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
       Get-vlSimpleExample
   #>

   # Define risk score ranges from 0 to 100 (100 is the highest risk). This should be static and not change during the test.
   $riskScore = 90

   # Add your test logic here, we just set a variable to true
   $result = $true

   # Define the score for this test. Score ranges from 0 to 10 (10 is the highest score = best result).
   # In this case, we set the score to 10, since the result is true.

   $score = 0 # Initialize the score variable

   if ($result) {
      $score = 10
   }
   else {
      $score = 0
   }

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlGroupSimilarValues() {
   <#
   .SYNOPSIS
       This test returns a grouped result.
   .DESCRIPTION
         This test returns a grouped result.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlGroupSimilarValues
   #>

   # Define risk score ranges from 0 to 100 (100 is the highest risk). This should be static and not change during the test.
   $riskScore = 90

   ### Case WIFI is enabled and connected
   $wifiStatus = "enabled"
   $wifiConnectionStatus = "connected"
   $wifiSSID = "MyWifi"
   $wifiEncryption = "WPA3"

   # check if wifiEncryption is WPA3 else give it a lower testScore
   if ($wifiEncryption -eq "WPA3") {
      $score = 10
   }
   else {
      $score = 5
   }

   # Initialize new result object and add the values to it
   $result = @{
      wifiStatus           = $wifiStatus
      wifiConnectionStatus = $wifiConnectionStatus
      wifiSSID             = $wifiSSID
      wifiEncryption       = $wifiEncryption
   }

   ## You would return the result object here, but we will return the result object in the next example.
   # return New-vlResultObject -result $result -score $score -riskScore $riskScore

   # Case WIFI is disabled
   $wifiStatus = "disabled"
   $wifiConnectionStatus = "not connected"

   # Case WIFI is disabled
   $result = @{
      wifiStatus           = $wifiStatus
      wifiConnectionStatus = $wifiConnectionStatus
   }

   # We do not need to add $wifiSSID and $wifiEncryption here, since they are not available if WIFI is disabled.
   # The dashboard will show n/a for these values if they are not present.

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlSimpleArrayExample() {
   <#
   .SYNOPSIS
       This test returns a simple result array.
   .DESCRIPTION
         This test returns a simple result array.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlSimpleArrayExample
   #>

   # Arrays can be used for tests. It is important to note that the dashboard currently does only support arrays as a top-level object.

   $score = 10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   $riskScore = 90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just create two objects and add them to the result array

   $resultObj1 = @{
      Name = "John"
      Age  = 30
   }

   $resultObj2 = @{
      Name = "Doe"
      Age  = 43
   }

   $result = @()
   $result += $resultObj1
   $result += $resultObj2

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlNestedExample() {
   <#
   .SYNOPSIS
       This test returns a nested result.
   .DESCRIPTION
         This test returns a nested result.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlNestedExample
   #>

   $score = 3 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   $riskScore = 70 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here
   # ...

   # Create result object, pass on $resultData to add values to the result
   $result = @{
      Enabled = $true
      CmdLine = "/bin/zsh -c 'if (2 -eq 2) { echo equals; }'"
   }

   $nestedObj = @{
      Name = "John"
      Age  = 30
   }

   # Add a nested object within the result object using key "Person"
   $result.Add("Person", $nestedObj)

   # While it is technically possible to add arrays to an nested object, the dashboard cannot display them correctly, so please avoid doing so.
   # Don't use code like: $result.Add("Members", @($nestedObj))

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}


function Get-vlSupportMatrixExample() {
   # JSON - Dashboard Support Matrix
   # The dashboard supports the following structures. Please use this example to check if your result can be displayed correctly.

   # Legend:
   # [+] Supported
   # [-] Not Supported

   # Structure                                                                         | Status
   # ----------------------------------------------------------------------------------|--------
   # Simple Object                                                                     | [+]
   #   {"Enabled": true, "Mode": "Auto"}
   # Code:

   # Create result object, pass on $resultData to add values to the result.
   $result = @{
      Enabled = $true
      Mode    = "Auto"
   }

   # ----------------------------------------------------------------------------------|--------
   # Array of Objects                                                                  | [+]
   #   [{"Name":"John","Age":30, "City":"New York"},
   #    {"Name":"Alice","Age":25, "City":"Los Angeles"}]
   # Code:

   $result = @(
      @{
         Name = "John"
         Age  = 30
         City = "New York"
      }
      @{
         Name = "Alice"
         Age  = 25
         City = "Los Angeles"
      }
   )

   # ----------------------------------------------------------------------------------|--------
   # Object with simple Array (Strings, Numbers)                                       | [+]
   #   {"Applications":["App1", "App2", "App3"], "Status": "Active"}
   # Code:

   $result = @{
      Applications = @("App1", "App2", "App3")
      Status       = "Active"
   }

   # ----------------------------------------------------------------------------------|--------
   # Complex Object                                                                    | [+]
   #   {"Enabled":true, "Config": {"Path":"/usr/bin", "Timeout":30},
   #    "User":{"Name":"John", "Role":"Admin"}}
   # Code:

   $result = @{
      Enabled = $true
      Config  = @{
         Path    = "/usr/bin"
         Timeout = 30
      }
      User    = @{
         Name = "John"
         Role = "Admin"
      }
   }

   # ----------------------------------------------------------------------------------|--------
   # Object with Array of Objects                                                      | [-]
   #   {"Team": "Developers",
   #    "Members": [{"Name":"John","Skill":"Java"},
   #                {"Name":"Alice","Skill":"Python"}
   #               ]}

   # While it is technically possible to add arrays to an nested object, the dashboard cannot display them correctly, so please avoid doing so.
   # Code to create such a result, that is not supported by the dashboard:

   $result = @{
      Team    = "Developers"
      Members = @(
         @{
            Name  = "John"
            Skill = "Java"
         }
         @{
            Name  = "Alice"
            Skill = "Python"
         }
      )
   }

   # ----------------------------------------------------------------------------------|--------

   $score = 10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   $riskScore = 90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlErrorExample() {
   <#
   .SYNOPSIS
       This test is made to fail to demonstrate how to handle errors.
   .DESCRIPTION
         This test is made to fail to demonstrate how to handle errors.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlErrorExample
   #>

   # Add your test logic here
   # ...

   $score = 0
   $riskScore = 90

   # Try to run a command that does not exist
   try {
      $result = Invoke-Expression "Get-NonExistingCommand"

      # We should never reach this point, since the command does not exist
      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      # Send empty result object, since the test failed.

      # Handle the error and return an error object.
      return New-vlErrorObject -context $_
   }
}


# Replace "Template" with the name of your module.
function Get-vlTemplateCheck {
   <#
    .SYNOPSIS
        Write a quick summary of what the function does here.
    .DESCRIPTION
        Write a description of the function here.
    .NOTES
         Additional information about the function.
    .LINK
        Provide a link to more information about the function or some related resource.
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlTemplateCheck
    #>

   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   if ($params.Contains("all") -or $params.Contains("vlSimpleExample")) {
      $vlSimpleExample = Get-vlSimpleExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlSimpleExample"
         DisplayName  = "Simple example"
         Description  = "This test returns a simple result."
         Score        = $vlSimpleExample.Score # Returned from the Test
         ResultData   = $vlSimpleExample.Result # Returned from the Test
         RiskScore    = $vlSimpleExample.RiskScore # Returned from the Test
         ErrorCode    = $vlSimpleExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlSimpleExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlGroupSimilarValues")) {
      $vlGroupSimilarValues = Get-vlGroupSimilarValues

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlGroupSimilarValues"
         DisplayName  = "Group values example"
         Description  = "This test returns a grouped result."
         Score        = $vlGroupSimilarValues.Score # Returned from the Test
         ResultData   = $vlGroupSimilarValues.Result # Returned from the Test
         RiskScore    = $vlGroupSimilarValues.RiskScore # Returned from the Test
         ErrorCode    = $vlGroupSimilarValues.ErrorCode # Returned from the Test
         ErrorMessage = $vlGroupSimilarValues.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlSimpleArrayExample")) {
      $vlSimpleArrayExample = Get-vlSimpleArrayExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlSimpleArrayExample"
         DisplayName  = "Simple array example"
         Description  = "This test returns a simple result array."
         Score        = $vlSimpleArrayExample.Score # Returned from the Test
         ResultData   = $vlSimpleArrayExample.Result # Returned from the Test
         RiskScore    = $vlSimpleArrayExample.RiskScore # Returned from the Test
         ErrorCode    = $vlSimpleArrayExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlSimpleArrayExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlNestedExample")) {
      $vlNestedExample = Get-vlNestedExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlNestedExample"
         DisplayName  = "Nested result"
         Description  = "This test returns a nested result."
         Score        = $vlNestedExample.Score # Returned from the Test
         ResultData   = $vlNestedExample.Result # Returned from the Test
         RiskScore    = $vlNestedExample.RiskScore # Returned from the Test
         ErrorCode    = $vlNestedExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlNestedExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlSupportMatrixExample")) {
      $vlSupportMatrixExample = Get-vlSupportMatrixExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlSupportMatrixExample"
         DisplayName  = "Matrix example"
         Description  = "This test returns a Matrix example."
         Score        = $vlSupportMatrixExample.Score # Returned from the Test
         ResultData   = $vlSupportMatrixExample.Result # Returned from the Test
         RiskScore    = $vlSupportMatrixExample.RiskScore # Returned from the Test
         ErrorCode    = $vlSupportMatrixExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlSupportMatrixExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlSupportMatrixExample")) {
      $vlErrorExample = Get-vlErrorExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlErrorExample"
         DisplayName  = "Error result"
         Description  = "This test is made to fail to demonstrate how to handle errors."
         Score        = $vlErrorExample.Score # Returned from the Test
         ResultData   = $vlErrorExample.Result # Returned from the Test
         RiskScore    = $vlErrorExample.RiskScore # Returned from the Test
         ErrorCode    = $vlErrorExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlErrorExample.ErrorMessage # Returned from the Test
      }
   }

   Write-Output $output
}


# Ensure that the output is in UTF-8 format, hacky way to handle older PowerShell versions.
try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlTemplateCheck | ConvertTo-Json -Compress)
