
vlUtils="./Utils.zsh"
. "$vlUtils" && vlInit


resultData=$(vlCreateResult)
resultData=$(vlAddResultValue "$resultData" "Person.Name" "John")
resultData=$(vlAddResultValue "$resultData" "Person.Age" "30")
resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["blue"]')
resultData=$(vlAddResultValue "$resultData" "Person.Colors" '["red","yellow"]')

arr='[1, 2, 3]'
resultData=$(vlAddResultValue "$resultData" "Numbers" "$arr")
resultData=$(vlAddResultValue "$resultData" "Numbers" '[4,5,6,7]')

echo "$resultData"