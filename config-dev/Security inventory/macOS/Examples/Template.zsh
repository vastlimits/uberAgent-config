
# JSON - Dashboard Support Matrix

# Legend:
# [+] Supported
# [-] Not Supported

# Structure                                                                         | Status
# ----------------------------------------------------------------------------------|--------
# Simple Object                                                                     | [+]
#   {"Enabled": true, "Mode": "Auto"}
# ----------------------------------------------------------------------------------|--------
# Array of Objects                                                                  | [+]
#   [{"Name":"John","Age":30, "City":"New York"},
#    {"Name":"Alice","Age":25, "City":"Los Angeles"}]
# ----------------------------------------------------------------------------------|--------
# Object with simple Array (Strings, Numbers)                                       | [+]
#   {"Applications":["App1", "App2", "App3"], "Status": "Active"}
# ----------------------------------------------------------------------------------|--------
# Complex Object                                                                    | [+]
#   {"Enabled":true, "Config": {"Path":"/usr/bin", "Timeout":30},
#    "User":{"Name":"John", "Role":"Admin"}}
# ----------------------------------------------------------------------------------|--------
# Object with Array of Objects                                                      | [-]
#   {"Team": "Developers",
#    "Members": [{"Name":"John","Skill":"Java"},
#                {"Name":"Alice","Skill":"Python"}
#               ]}
# ----------------------------------------------------------------------------------|--------

vlSimpleExample()
{
   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   testName="vlSimpleExample" # give the test a unique name
   testDisplayName="Simple example" # give the test a human-readable name, this will be displayed on the dashboard
   testDescription="This test returns a simple result." # give the test a description

   testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just set a variable to true
   result="true"

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

   resultData=$(vlAddResultValue "{}" "Enabled" $result)

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlSimpleArrayExample()
{
   # Arrays can be used for tests. It is important to note that the dashboard currently does only support arrays as a top-level object.

   # Please always use this block, which consists of testName, testDisplayName, and testDescription.
   # Important for the pipeline, these values are parsed and displayed on the dashboard.
   testName="vlSimpleArrayExample" # give the test a unique name
   testDisplayName="Simple array example" # give the test a human-readable name, this will be displayed at the dashboard
   testDescription="This test returns a simple result array." # give the test a description

   testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just create two objects and add them to the result array
   resultObj1=$(vlAddResultValue "{}" "Name" "John")
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
   resultData=$(vlAddResultValue "[]" "" "[$resultObj1, $resultObj2]")

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
   testName="vlNestedExample" # give the test a unique name
   testDisplayName="Nested result" # give the test a human-readable name, this will be displayed at the dashboard
   testDescription="This test returns a nested result." # give the test a description

   testScore=3 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   riskScore=70 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here
   # ...

   # Create result object, pass on $resultData to add values to the result
   resultData=$(vlAddResultValue "{}" "Enabled" true)
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

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()
results+="$( vlSimpleExample )"
results+="$( vlSimpleArrayExample )"
results+="$( vlNestedExample )"

# Print the results as JSON
vlPrintJsonReport "${results[@]}"