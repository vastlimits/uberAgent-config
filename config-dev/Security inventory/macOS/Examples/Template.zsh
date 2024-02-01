
vlSimpleExample()
{
   # Please always use this block constisting of testName, testDisplayName and testDescription.
   # Important for the piepline, these values are parsed and displayed on the dashboard.
   testName="vlSimpleExample" # give the test a unique name
   testDisplayName="Simple example" # give the test a human-readable name, this will be displayed at the dashboard
   testDescription="This test returns a simple result." # give the test a description

   testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here, we just set a variable to true
   result="true"

   # Add the result of your logic to the final output using vlAddResultValue
   # The parameters for vlAddResultValue are: $resultData, $key, $value
   #  $resultData should be passed from call to call and contains the result object, use "{}" to create a new result object or "[]" to create a new result array
   #  $value is the value you want to add
   resultData=$(vlAddResultValue "{}" "Enabled" $result)

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlSimpleArrayExample()
{
   # Arrays can be used for tests. It is important to note that the dashboard currrently does only support arrays as a top-level object.

   # Please always use this block constisting of testName, testDisplayName and testDescription.
   # Important for the piepline, these values are parsed and displayed on the dashboard.
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
   #  $resultData should be passed from call to call and contains the result object, use "{}" to create a new result object or "[]" to create a new result array
   #  $value is the value you want to add

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
   # Please always use this block constisting of testName, testDisplayName and testDescription.
   # The pipeline will try to parse these values and display them in the dashboard.
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

   # While adding arrays to an object is technically possible, the dashboard will not display this correctly so please avoid this.
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