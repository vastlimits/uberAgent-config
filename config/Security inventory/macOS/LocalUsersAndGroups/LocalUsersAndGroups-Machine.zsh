#
# Security and Compliance Inventory: Local users and groups
#

vlCheckAutoLogin()
{
  local testName="AutoLoginStatus"
  local testDisplayName="Auto Login Status"
  local testDescription="Auto login is a feature that allows a user to automatically log into their account without entering their password upon system startup. This test checks if the feature is enabled."
  local testScore=10
  local riskScore=100
  
  local loginStatus="disabled"
  local autoLoginUser=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
  if [[ -n "$autoLoginUser" ]]; then
    loginStatus="enabled"
    testScore=0
  fi
  
  resultData=$(vlAddResultValue "{}" "Status" "$loginStatus")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckUserNamesShownOnLogin()
{
  local testName="UserNamesShownOnLogin"
  local testDisplayName="User names shown on login"
  local testDescription="This test determines if a list of users is presented on the login window. Displaying a list at login can be a security threat as it provides potential attackers with valid usernames, which can be used for password-guessing or social engineering attacks."
  local testScore=10
  local riskScore=60
  
  local requireManualEntry=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null)
  local userListShown="true"
  
  if [[ -z "$requireManualEntry" ]]; then
    # If the command does not succeed because the pair does not exist (due to this option not having been changed at least once), we have to assume the default.
    testScore=4
    userListShown="true"
  elif [[ "$requireManualEntry" == "1" ]]; then
    userListShown="false"
  else
    userListShown="true"
    testScore=4
  fi
  
  resultData=$(vlAddResultValue "{}" "User list shown" "$userListShown")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckForDefaultPasswordPolicy()
{
  local testName="DefaultPasswordPolicyUsed"
  local testDisplayName="Default Password Policy Used"
  local testDescription="This test determines if the default macOS password policy is used. This policy allows empty passwords (on unencrypted devices) and passwords with a minimum length of four characters (on devices with FileVault enabled)."
  local testScore=10
  local riskScore=100
  
  # Get the account policies using pwpolicy
  local policyOutput=$(pwpolicy -getaccountpolicies)
  
  # Define the string that identifies the default password policy
  local defaultPolicyIdentifier="<string>com.apple.defaultpasswordpolicy"
  
  # Check if the default policy identifier is in the policy output
  local defaultPolicyUsed="true"
  if [[ $policyOutput == *"$defaultPolicyIdentifier"* ]]; then
    testScore=0
  else
    defaultPolicyUsed="false"
  fi
  
  resultData=$(vlAddResultValue "{}" "Default Policy Used" "$defaultPolicyUsed")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()
results+="$( vlCheckAutoLogin )"
results+="$( vlCheckUserNamesShownOnLogin )"
results+="$( vlCheckForDefaultPasswordPolicy )"
# Print the results as JSON
vlPrintJsonReport "${results[@]}"