#
# Security and Compliance Inventory: Antivirus status
#

vlCheckGatekeeper()
{
  local testName="GatekeeperStatus"
  local testDisplayName="Gatekeeper Status"
  local testDescription="Gatekeeper is a security feature designed to ensure that only trusted software, verified as safe by Apple, can be run on the system. This test checks if Gatekeeper is enabled and which app sources are allowed."
  local testScore=10
  local riskScore=100
  
  local gatekeeperStatus="enabled"
  local gatekeeperOption="App Store"
   
  # Check if Gatekeeper is enabled
  gatekeeper_status=$(spctl --status)
  if [[ $gatekeeper_status == "assessments enabled" ]]; then
  
      # Check for developer ID status
      developer_id_status=$(spctl --status -v)
  
      if [[ $developer_id_status == *"developer id enabled"* ]]; then
          gatekeeperOption="App Store and identified developers"
      elif [[ $developer_id_status == *"developer id disabled"* ]]; then
          gatekeeperOption="App Store"
          testScore=8
      else
          gatekeeperOption="unknown"
          testScore=5
      fi
      
      resultData=$(vlAddResultValue "{}" "Status" "$gatekeeperStatus")
      resultData=$(vlAddResultValue "$resultData" "Allows apps from" "$gatekeeperOption")  
  else
      gatekeeperStatus="disabled"
      testScore=0
      resultData=$(vlAddResultValue "{}" "Status" "$gatekeeperStatus")
  fi
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckXprotectRemediator()
{
  local testName="XProtectRemediatorStatus"
  local testDisplayName="XProtect Remediator Status"
  local testDescription="XProtect Remediator is a security feature within macOS that helps detect and remove malware and other threats from the system. This test checks its version and last modification date."
  local testScore=10
  local riskScore=100
  
  local version="unknown"
  local lastModified=""
  
  # Path to the XProtect.plist
  xprotect_plist="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
  
  # Check if the XProtect.plist exists
  if [[ -f "$xprotect_plist" ]]; then
    # Retrieve the version of the XProtect Remediator
    version=$(defaults read "$xprotect_plist" Version)
    
    # Check if the version retrieval was successful
    if [[ $? -ne 0 ]]; then
      testScore=5
      version="unknown"
    fi
  
    # Retrieve and display the last modification date of the plist file
    lastModified=$(stat -f "%Sm" -t "%Y-%m-%d" "$xprotect_plist")
    
    #resultObj1=$(vlAddResultValue "{}" "Version" "$version")
    #resultObj2=$(vlAddResultValue "{}" "Last update" "$lastModified")
    #resultData=$(vlAddResultValue "[]" "" "[$resultObj1, $resultObj2]")
    
    resultData=$(vlAddResultValue "{}" "Version" "$version")
    resultData=$(vlAddResultValue "$resultData" "Last update" "$lastModified")
    
  else
    testScore=0
    resultData=$(vlAddResultValue "{}" "Status" "$gatekeeperStatus")
  fi
 
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()
results+="$( vlCheckGatekeeper )"
results+="$( vlCheckXprotectRemediator )"
# Print the results as JSON
vlPrintJsonReport "${results[@]}"