
vlUtils="/Utils.zsh"
. "$vlUtils" && vlInit


resultData=$(vlCreateResult)
resultData=$(vlAddResultValue "$resultData" "Person.Name" "John")
resultData=$(vlAddResultValue "$resultData" "Person.Age" "30")

# Für Arrays, stellen Sie sicher, dass das Array im JSON-Format vorliegt
arr='["Apfel", "Banane", "Kirsche"]'
resultData=$(vlAddResultValue "$resultData" "Fruits" "$arr")


echo "$resultData"