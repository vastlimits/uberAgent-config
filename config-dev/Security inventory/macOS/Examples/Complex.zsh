
vlUtils="./../Utils.zsh"
. "$vlUtils" && vlInit

# Create complex Result
resultData=$(vlAddResultValue "" "Enabled" true)
resultData=$(vlAddResultValue "$resultData" "CmdLine" "/bin/bash -c \"if [ 2 -eq 2 ]; then echo equals; fi;\"")
resultData=$(vlAddResultValue "$resultData" "Person.Name" "John")
resultData=$(vlAddResultValue "$resultData" "Person.Age" 30)
resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["blue"]')
resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["red","yellow"]')

arr='[1, 2, 3]'
resultData=$(vlAddResultValue "$resultData" "Numbers" "$arr")
resultData=$(vlAddResultValue "$resultData" "Numbers" '[4,5,6,7]')

# Test vlCreateResultObject
testName="Test1"
testDisplayName="Test Display Name"
testDescription="This is a test"
testScore=85
riskScore=20

resultJSON=$(vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData")

# Echo result object
results=()
results+="$resultJSON"

vlPrintJsonReport "${results[@]}"