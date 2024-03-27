
# This file should help you to get started with writing SCI tests for macOS.

#
# To ensure that data is displayed accurately in the Security Score Splunk dashboard, it's important to follow certain best practices.
#
# 1)  A key practice is to aggregate related values within a test and return the result as a single object.
#     This approach simplifies the analysis and visualization of data, especially when examining related metrics or statuses.
#
#     This allows you to handle dependencies, such as only getting the SSID and encryption method when WIFI is enabled and connected.
#     If you separated these values into separate tests (WIFI enabled, current SSID, encryption method), it would be more difficult to calculate the risk score and merge the data.
#
#     Example: vlGroupSimilarValues.
#
# 2)  Splunk has a default limit of 10,000 characters for a single event; data is truncated if it exceeds this limit.
#     If you expect a result to exceed this limit, consider breaking it into smaller, more manageable pieces.
#
# 3)  The Security Score Splunk dashboard currently does not support every json structure.
#
#     Example: vlSupportMatrixExample.
#

vlSimpleExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlSimpleExample" # give the test a unique name
   local testDisplayName="Simple example" # give the test a human-readable name, this will be displayed on the dashboard
   local testDescription="This test returns a simple result." # give the test a description

   local testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   local riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just set a variable to true
   local result="true"

   # Add the result of your logic to the final output using vlAddResultValue

   # The parameters for vlAddResultValue are: $resultData, $key, $value
   #
   #  $resultData:
   #     Should be passed from call to call and contains the result object, use "{}" to create a new result object or "[]" to create a new result array.
   #     In this case, we use an object and add the Enabled property. Please see vlSimpleArrayExample for an array example.
   #  $key:
   #     The key under which the value should be added. Leave empty if you want to add a value to an array. Please see vlSimpleArrayExample for an array example.
   #  $value:
   #     Is the value you want to add. In this case, we want to add the value of $result.

   local resultData=$(vlAddResultValue "{}" "Enabled" $result)

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlGroupSimilarValues()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlGroupSimilarValues" # give the test a unique name
   local testDisplayName="Group values example" # give the test a human-readable name, this will be displayed on the dashboard
   local testDescription="This test returns a grouped result." # give the test a description

   local testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   local riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just set a variable to true

   # Case WIFI is enabled and connected
   local wifiStatus="enabled"
   local wifiConnectionStatus="connected"
   local wifiSSID="MyWifi"
   local wifiEncryption="WPA3"

   # check if wifiEncryption is WPA3 else give it a lower testScore
   if [ "$wifiEncryption" != "WPA3" ]; then
      testScore=5
   fi

   # Initialize new result object and add the values to it
   local resultData=$(vlAddResultValue "{}" "wifiStatus" "$wifiStatus")
   resultData=$(vlAddResultValue "$resultData" "wifiConnectionStatus" "$wifiConnectionStatus")
   resultData=$(vlAddResultValue "$resultData" "wifiSSID" "$wifiSSID")
   resultData=$(vlAddResultValue "$resultData" "wifiEncryption" "$wifiEncryption")

   # Case WIFI is disabled
   local wifiStatus="disabled"
   local wifiConnectionStatus="not connected"

   # Case WIFI is disabled
   resultData=$(vlAddResultValue "{}" "wifiStatus" "$wifiStatus")
   resultData=$(vlAddResultValue "$resultData" "wifiConnectionStatus" "$wifiConnectionStatus")

   # We do not need to add $wifiSSID and $wifiEncryption here, since they are not available if WIFI is disabled.
   # The dashboard will show n/a for these values if they are not present.

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlSimpleArrayExample()
{
   # Arrays can be used for tests. It is important to note that the dashboard currently does only support arrays as a top-level object.

   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlSimpleArrayExample" # give the test a unique name
   local testDisplayName="Simple array example" # give the test a human-readable name, this will be displayed at the dashboard
   local testDescription="This test returns a simple result array." # give the test a description

   local testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   local riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just create two objects and add them to the result array
   local resultObj1=$(vlAddResultValue "{}" "Name" "John")
   resultObj1=$(vlAddResultValue "$resultObj1" "Age" "30")

   resultObj2=$(vlAddResultValue "{}" "Name" "Doe")
   resultObj2=$(vlAddResultValue "$resultObj2" "Age" "43")

   # Add the result of your logic to the final output using vlAddResultValue

   # The parameters for vlAddResultValue are: $resultData, $key, $value
   #
   #  $resultData:
   #     Should be passed from call to call and contains the result object, use "{}" to create a new result object or "[]" to create a new result array.
   #     In this case, we add two objects to the result array. Please see vlSimpleExample or vlNestedExample for an object example.
   #  $key:
   #     The key under which the value should be added. Leave empty if you want to add a value to an array.
   #  $value:
   #     The value you want to add. In this case, we want to add the two objects we created above.

   # Option 1 all at once. Use "[]" to create a new array, since there is no key within an array leave key empty.
   local resultData=$(vlAddResultValue "[]" "" "[$resultObj1, $resultObj2]")

   # Option 2 one by one. Use "[]" to create a new array, then pass $resultData. Since there is no key within an array leave key empty.
   resultData=$(vlAddResultValue "[]" "" "[$resultObj1]")
   resultData=$(vlAddResultValue "$resultData" "" "[$resultObj2]")

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlNestedExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlNestedExample" # give the test a unique name
   local testDisplayName="Nested result" # give the test a human-readable name, this will be displayed at the dashboard
   local testDescription="This test returns a nested result." # give the test a description

   local testScore=3 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   local riskScore=70 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here
   # ...

   # Create result object, pass on $resultData to add values to the result
   local resultData=$(vlAddResultValue "{}" "Enabled" true)
   resultData=$(vlAddResultValue "$resultData" "CmdLine" "/bin/zsh -c \"if [ 2 -eq 2 ]; then echo equals; fi;\"")

   # Add a nested object
   resultData=$(vlAddResultValue "$resultData" "Person.Name" "John")
   resultData=$(vlAddResultValue "$resultData" "Person.Age" 30)

   # While it is technically possible to add arrays to an nested object, the dashboard cannot display them correctly, so please avoid doing so.
   # resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["blue"]')
   # resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["red","yellow"]')

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckFeatureStateFromCommandOutputExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlCheckFeatureStateFromCommandOutputExample" # give the test a unique name
   local testDisplayName="Check feature state from command output" # give the test a human-readable name, this will be displayed at the dashboard
   local testDescription="This test checks the state of a feature from the command output." # give the test a description

   local testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   local riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Define the expected output
   local expectedOutput="enabled"

   # Define the expected grep status (0 for success, 1 for failure)
   local expectedGrepStatus=0

   # Define the expected test result data value
   local expectedTestResultDataValue=true

   # Define the variable name that will be used in the result object
   local testResultVarName='Enabled'

   # Run the command, the last parameter is the command to run.
   # The function automatically generates the result object and reports an error if the command failed.
   vlCheckFeatureStateFromCommandOutput \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$riskScore" \
      "$expectedOutput" \
      "$expectedGrepStatus" \
      "$expectedTestResultDataValue" \
      "$testResultVarName" \
      /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
}

vlCheckFeatureEnabledFromPlistDomainKeyExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlCheckFeatureEnabledFromPlistDomainKeyExample" # give the test a unique name
   local testDisplayName="Check feature enabled from plist domain key" # give the test a human-readable name, this will be displayed at the dashboard
   local testDescription="This test checks the state of a feature from a plist domain key." # give the test a description

   local testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   local riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Define the plist domain
   local plistDomain="/Library/Preferences/com.apple.commerce"

   # Define the plist key
   local plistKey="AutoUpdate"

   # Define the default value if the key is not found
   local plistDefault=0

   # The function automatically generates the result object and reports an error if the command failed.
   vlCheckFeatureEnabledFromPlistDomainKey \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$riskScore" \
      "$plistDomain" \
      "$plistKey" \
      $plistDefault
}

vlSupportMatrixExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlSupportMatrixExample" # give the test a unique name
   local testDisplayName="Matrix example" # give the test a human-readable name, this will be displayed on the dashboard
   local testDescription="This test returns a Matrix example." # give the test a description

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
   # Use "{}" to create a new result object.
   # Use "[]" to create a new result array.
   local resultData=$(vlAddResultValue "{}" "Enabled" true)
   # resultData after call: {"Enabled": true}

   resultData=$(vlAddResultValue "$resultData" "Mode" "Auto")
   # resultData after call: {"Enabled": true, "Mode": "Auto"}

   # ----------------------------------------------------------------------------------|--------
   # Array of Objects                                                                  | [+]
   #   [{"Name":"John","Age":30, "City":"New York"},
   #    {"Name":"Alice","Age":25, "City":"Los Angeles"}]
   # Code:

   # Create result object, pass on $resultData to add values to the result.
   resultData=$(vlAddResultValue "[]" "" '{"Name":"John","Age":30, "City":"New York"}')
   # resultData after call: [{"Name":"John","Age":30, "City":"New York"}]

   resultData=$(vlAddResultValue "$resultData" "" '{"Name":"Alice","Age":25, "City":"Los Angeles"}')
   # resultData after call: [{"Name":"John","Age":30, "City":"New York"}, {"Name":"Alice","Age":25, "City":"Los Angeles"}]

   # ----------------------------------------------------------------------------------|--------
   # Object with simple Array (Strings, Numbers)                                       | [+]
   #   {"Applications":["App1", "App2", "App3"], "Status": "Active"}
   # Code:

   # Create result object, pass on $resultData to add values to the result.
   resultData=$(vlAddResultValue "{}" "Applications" '["App1", "App2", "App3"]')
   # resultData after call: {"Applications":["App1", "App2", "App3"]}

   resultData=$(vlAddResultValue "$resultData" "Status" "Active")
   # resultData after call: {"Applications":["App1", "App2", "App3"], "Status": "Active"}

   # ----------------------------------------------------------------------------------|--------
   # Complex Object                                                                    | [+]
   #   {"Enabled":true, "Config": {"Path":"/usr/bin", "Timeout":30},
   #    "User":{"Name":"John", "Role":"Admin"}}
   # Code:

   # Create result object, pass on $resultData to add values to the result.
   resultData=$(vlAddResultValue "{}" "Enabled" true)
   # resultData after call: {"Enabled": true}

   resultData=$(vlAddResultValue "$resultData" "Config.Path" "/usr/bin")
   # resultData after call: {"Enabled": true, "Config": {"Path":"/usr/bin"}}

   resultData=$(vlAddResultValue "$resultData" "Config.Timeout" 30)
   # resultData after call: {"Enabled": true, "Config": {"Path":"/usr/bin", "Timeout":30}}

   resultData=$(vlAddResultValue "$resultData" "User.Name" "John")
   # resultData after call: {"Enabled": true, "Config": {"Path":"/usr/bin", "Timeout":30}, "User.Name": "John"}

   resultData=$(vlAddResultValue "$resultData" "User.Role" "Admin")
   # resultData after call: {"Enabled": true, "Config": {"Path":"/usr/bin", "Timeout":30}, "User.Name": "John", "User.Role": "Admin"}

   # ----------------------------------------------------------------------------------|--------
   # Object with Array of Objects                                                      | [-]
   #   {"Team": "Developers",
   #    "Members": [{"Name":"John","Skill":"Java"},
   #                {"Name":"Alice","Skill":"Python"}
   #               ]}

   # While it is technically possible to add arrays to an nested object, the dashboard cannot display them correctly, so please avoid doing so.
   # Code to create such a result:
   resultData=$(vlAddResultValue "{}" "Team" "Developers")
   resultData=$(vlAddResultValue "$resultData" "Members" '[]')
   resultData=$(vlAddResultValue "$resultData" "Members" '[{"Name":"John","Skill":"Java"}]')
   resultData=$(vlAddResultValue "$resultData" "Members" '[{"Name":"Alice","Skill":"Python"}]')

   # ----------------------------------------------------------------------------------|--------
}

vlErrorExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   local testName="vlErrorExample" # give the test a unique name
   local testDisplayName="Error result" # give the test a human-readable name, this will be displayed at the dashboard
   local testDescription="This test is made to fail to demonstrate how to handle errors." # give the test a description

   # Add your test logic here
   # ...

   # Try to run a command that does not exist
   vlRunCommand /run/not/existing/command

   # Check if the command was successful and report an error if not
   if (( $vlCommandStatus != 0 )); then
      vlReportErrorJson \
         "$testName" \
         "$testDisplayName" \
         "$testDescription" \
         "$vlCommandStatus" \
         "$vlCommandStderr"
      return
   fi
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()
results+="$( vlSimpleExample )"
results+="$( vlGroupSimilarValues )"
results+="$( vlSimpleArrayExample )"
results+="$( vlNestedExample )"
results+="$( vlCheckFeatureStateFromCommandOutputExample )"
results+="$( vlCheckFeatureEnabledFromPlistDomainKeyExample )"
results+="$( vlErrorExample )"

# Print the results as JSON
vlPrintJsonReport "${results[@]}"