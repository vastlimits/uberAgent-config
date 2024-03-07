#
# Security and Compliance Inventory: Operating system configuration 
#

vlCheckFVStatus()
{
   local testName="FVStatus"
   local testDisplayName="FileVault Status"
   local testDescription="FileVault secures the data on a machines disk by encrypting its content automatically. It is recommended to turn it on, especially for mobile devices. This test checks if FileVault is enabled."
   local testScore=10
   local riskScore=80

   local expectedOutput="FileVault is On."
   local expectedGrepStatus=0
   local expectedTestResultDataValue=true
   local testResultVarName='Enabled'

   vlCheckFeatureStateFromCommandOutput \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$riskScore" \
      "$expectedOutput" \
      "$expectedGrepStatus" \
      "$expectedTestResultDataValue" \
      "$testResultVarName" \
      fdesetup status
}

vlCheckSipStatus()
{
   local testName="SIPStatus"
   local testDisplayName="System Integrity Protection Status"
   local testDescription="System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code. This test checks if SIP is enabled."
   local testScore=10
   local riskScore=100

   local expectedOutput="System Integrity Protection status: enabled."
   local expectedGrepStatus=0
   local expectedTestResultDataValue=true
   local testResultVarName='Enabled'

   vlCheckFeatureStateFromCommandOutput \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$riskScore" \
      "$expectedOutput" \
      "$expectedGrepStatus" \
      "$expectedTestResultDataValue" \
      "$testResultVarName" \
      csrutil status
}

vlCheckFWPWStatus()
{
   local testName="FWPWStatus"
   local testDisplayName="macOS firmware password status"
   local testDescription="Without a firmware password system startup from any disk other than the designated startup disk is not possible. This feature requires a Mac with an Intel processor. This test checks if a firmware password is set."
   local testScore=10
   local riskScore=60

   local architecture=$(uname -m)
   local hwModel=$(sysctl -n hw.model)
   local virtualIdentifiers=("virtual" "vmware" "parallels" "vbox") 
   local isPhysical="true"

   for identifier in "${virtualIdentifiers[@]}"; do
      if [[ "$hwModel:l" == *"$identifier:l"* ]]; then
         isPhysical="false"
         break
      fi
   done

   # Firmware passwords are not available on Apple Silicon Macs and virtual machines.
   if [[ "$architecture" == "x86_64" && "$isPhysical" == "true" ]]; then
      local expectedOutput="Password Enabled: Yes"
      local expectedGrepStatus=0
      local expectedTestResultDataValue=true
      local testResultVarName='Enabled'

      vlCheckFeatureStateFromCommandOutput \
         "$testName" \
         "$testDisplayName" \
         "$testDescription" \
         "$riskScore" \
         "$expectedOutput" \
         "$expectedGrepStatus" \
         "$expectedTestResultDataValue" \
         "$testResultVarName" \
         firmwarepasswd -check
   fi
}

vlCheckPwForSwSettings()
{
   local testName="PwForSwSettings"
   local testDisplayName="Systemwide settings access"
   local testDescription="Some preferences in macOS contain settings that affect the entire system. Requiring a password to unlock these systemwide settings reduces the risk of a non-authorized user modifying system configurations. This test checks if a password is required."
   local testScore=10
   local riskScore=100

   # taken from: https://github.com/usnistgov/macos_security 
   authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
   result="true"
   for section in ${authDBs[@]}; do
      if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
      result="false"
      fi
   done

   if [ "$result" = "false" ]; then
      testScore=$( vlGetMinScore "$riskScore" )
   fi

   resultData=$(vlAddResultValue "{}" "Enabled" $result)

   # Create the result object
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckTmEnc()
{
   local testName="TmEnc"
   local testDisplayName="Time Machine backup encryption"
   local testDescription="This test checks if the Time Machine backup encryption is enabled. A backup needs to be present for this check to work."
   local testScore=10
   local riskScore=70

   # Check if Time Machine is enabled
   vlRunCommand tmutil destinationinfo
   
   if (( $vlCommandStatus != 0 )); then
      vlReportErrorJson \
         "$testName" \
         "$testDisplayName" \
         "$testDescription" \
         "$vlCommandStatus" \
         "$vlCommandStderr"
      return
   else
      if echo $vlCommandStdout | grep -q "Mount Point"; then
         local backupMountPoint=$(tmutil destinationinfo | awk -F': ' '/Mount Point/{print substr($0, index($0, $2))}')
         vlRunCommand diskutil list $backupMountPoint
         if (( $vlCommandStatus != 0 )); then
            vlReportErrorJson \
               "$testName" \
               "$testDisplayName" \
               "$testDescription" \
               "$vlCommandStatus" \
               "$vlCommandStderr"
            return
         else
            local backupEncrypted=$(diskutil info $backupMountPoint | grep "FileVault" | awk '{print $2}')
            if (( $backupEncrypted == "Yes" )); then
               result="true"
               resultData=$(vlAddResultValue "{}" "Enabled" $result)
            else
               result="false"
               testScore=$(vlGetMinScore "$riskScore")
               resultData=$(vlAddResultValue "{}" "Enabled" $result)
            fi
         fi
         # Create the result object
         vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
      fi
   fi 
}

vlCheckSecureEntry()
{
   local testName="SecureEntry"
   local testDisplayName="Terminal Secure Keyboard Entry"
   local testDescription="Secure Keyboard Entry can prevent other apps on the computer or network from detecting and recording what is typed in Terminal. This test checks if Secure Keyboard Entry is enabled."
   local testScore=10
   local riskScore=30

   # Get all real local users.
   local users=($(dscacheutil -q user | grep -A 3 -B 2 -e 'uid: [5-9][0-9]\{2\}\|uid: 1[0-9]\{3\}' | grep 'name:' | cut -d: -f2 | tr -d ' '))
   for user in $users
      do
         vlRunCommand sudo -u $user defaults read -app Terminal SecureKeyboardEntry         
         resultObj=$(vlAddResultValue "{}" "User" $user)
         if [[ $vlCommandStatus == 0 ]]; then
               result=$([[ $vlCommandStdout == 0 ]] && echo "true" || echo "false")
               resultObj=$(vlAddResultValue $resultObj "Enabled" $result)
         else
            if [[ $vlCommandStderr == *"The domain/default pair of (com.apple.Terminal, SecureKeyboardEntry) does not exist"* ]]; then
               result="false"
               resultObj=$(vlAddResultValue $resultObj "Enabled" $result)
            # If $vlCommandStatus != 0 and the error message is unexpected, we report an error. 
            else
               vlReportErrorJson \
                  "$testName" \
                  "$testDisplayName" \
                  "$testDescription" \
                  "$vlCommandStatus" \
                  "$vlCommandStderr"
               return
            fi
         fi

         if [[ $result == "false" ]]; then
            testScore=$(vlGetMinScore "$riskScore")
         fi

         # If this is not the first loop iteration, we can add $resultData to the existing array. Otherwise, we create a new array. 
         if [[ -n $resultData ]]
         then
            resultData=$(vlAddResultValue "$resultData" "" "[$resultObj]")
         else
            resultData=$(vlAddResultValue "[]" "" "[$resultObj]")   
         fi
      done  

   # Create the final result object for this test.
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckSmbSharing()
{
   local testName="SmbSharing"
   local testDisplayName="SMB sharing"
   local testDescription="Local shares can be a security risk as they might allow unauthorized access to sensitive data if not properly configured or if weak passwords are used. This test checks if SMB sharing is enabled."
   local testScore=10
   local riskScore=50

   result="false"
   # Check if SMB sharing is enabled
   local smbStatus="$(sudo launchctl list | grep com.apple.smbd)"
   if [[ $smbStatus == *"com.apple.smbd"* ]]; then
      testScore=$( vlGetMinScore "$riskScore" )
      result="true"
   fi

   resultData=$(vlAddResultValue "{}" "Enabled" $result)

   # Create the final result object for this test.
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}   

vlCheckMediaSharing()
{
   local testName="MediaSharing"
   local testDisplayName="Media sharing"
   local testDescription="Media sharing can pose a security risk because it may allow unauthorized access to sensitive content and exploit potential software vulnerabilities, leading to misuse of shared media. This test checks if media sharing is enabled."
   local riskScore=30
   local testScore=10

   # Get all real local users.
   local users=($(dscacheutil -q user | grep -A 3 -B 2 -e 'uid: [5-9][0-9]\{2\}\|uid: 1[0-9]\{3\}' | grep 'name:' | cut -d: -f2 | tr -d ' '))
   for user in $users
      do
         # Retrieve media sharing preferences for a given user.
         if [ -e /Users/$user/Library/Preferences/com.apple.amp.mediasharingd.plist ]; then
            vlRunCommand sudo -u $user defaults read com.apple.amp.mediasharingd         
            resultObj=$(vlAddResultValue "{}" "User" $user)
            if [[ $vlCommandStatus == 0 ]]; then
               # Parse the output to get the status of home and public sharing preferences.
               local homeSharing=$(echo $vlCommandStdout | grep -o '"home-sharing-enabled" = [0-1];' | awk -F'= ' '{print $2}' | sed 's/;//')
               local publicSharing=$(echo $vlCommandStdout | grep -o '"public-sharing-enabled" = [0-1];' | awk -F'= ' '{print $2}' | sed 's/;//')
                  # Check if both homeSharing and publicSharing are disabled, else consider media sharing as enabled.
                  if [[ (-z "$homeSharing" || "$homeSharing" == "0") && (-z "$publicSharing" || "$publicSharing" == "0") ]]; then
                     result="false"
                     resultObj=$(vlAddResultValue $resultObj "Enabled" $result)
                  else
                     result="true"   
                     resultObj=$(vlAddResultValue $resultObj "Enabled" $result)
                  fi
            # If $vlCommandStatus != 0, report an error.
            else
               testScore=$(vlGetMinScore "$riskScore")
               vlReportErrorJson \
                  "$testName" \
                  "$testDisplayName" \
                  "$testDescription" \
                  "$vlCommandStatus" \
                  "$vlCommandStderr"
               return
            fi
         # If the plist is not present assume the default, e.g. Media Sharing is disabled.
         else
            result="false"
            resultObj=$(vlAddResultValue "{}" "User" $user)
            resultObj=$(vlAddResultValue $resultObj "Enabled" $result)
         fi
         
         # If this is not the first loop iteration, we can add $resultData to the existing array. Otherwise, we create a new array. 
         if [[ -n $resultData ]]
         then
            resultData=$(vlAddResultValue "$resultData" "" "[$resultObj]")
         else
            resultData=$(vlAddResultValue "[]" "" "[$resultObj]")   
         fi
      done  

   # Create the final result object for this test.
   vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()
results+="$( vlCheckFVStatus )"
results+="$( vlCheckSipStatus )"
results+="$( vlCheckFWPWStatus )"
results+="$( vlCheckPwForSwSettings )"
results+="$( vlCheckTmEnc )"
results+="$( vlCheckSecureEntry )"
results+="$( vlCheckSmbSharing )"
results+="$( vlCheckMediaSharing )"

# Print the results as JSON
vlPrintJsonReport "${results[@]}"