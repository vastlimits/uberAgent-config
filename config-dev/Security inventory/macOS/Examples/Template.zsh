
vlSimpleExample()
{
   # Please always use this block constisting of testName, testDisplayName and testDescription.
   # Important for the piepline, these values are parsed and displayed on the dashboard.
   testName="vlSimpleExample" # give the test a unique name
   testDisplayName="Simple result" # give the test a human-readable name, this will be displayed at the dashboard
   testDescription="This test returns a simple result." # give the test a description

   testScore=10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   riskScore=90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk score).

   # Add your test logic here, we just set a variable to true
   result="true"

   # Add the result of your logic to the final output using vlAddResultValue
   # The parameters for vlAddResultValue are: $resultData, $key, $value
   #  $resultData should be passed from call to call and contains the result object, if empty a new result object will be created
   #  $key is the key of the value you want to add
   #  $value is the value you want to add
   resultData=$(vlAddResultValue "" "Enabled" $result)

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlComplexExample()
{
   # Please always use this block constisting of testName, testDisplayName and testDescription.
   # The pipeline will try to parse these values and display them in the dashboard.
   testName="vlComplexExample" # give the test a unique name
   testDisplayName="Complex result" # give the test a human-readable name, this will be displayed at the dashboard
   testDescription="This test returns a complex result." # give the test a description

   testScore=3 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   riskScore=70 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk score).

   # Add your test logic here
   # ...

   # Create complex Result, pass on $resultData to add values to the result
   resultData=$(vlAddResultValue "" "Enabled" true)
   resultData=$(vlAddResultValue "$resultData" "CmdLine" "/bin/zsh -c \"if [ 2 -eq 2 ]; then echo equals; fi;\"")

   # Add a nested object
   resultData=$(vlAddResultValue "$resultData" "Person.Name" "John")
   resultData=$(vlAddResultValue "$resultData" "Person.Age" 30)

   # Add an array of strings
   resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["blue"]')

   # This will append the array to the existing array
   resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["red","yellow"]')

   # arrays of other types are also supported
   arr='[1, 2, 3]'
   resultData=$(vlAddResultValue "$resultData" "Numbers" "$arr")

   # This will append the array to the existing array
   resultData=$(vlAddResultValue "$resultData" "Numbers" '[4,5,6,7]')

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()
results+="$( vlSimpleExample )"
results+="$( vlComplexExample )"

# Print the results as JSON
vlPrintJsonReport "${results[@]}"