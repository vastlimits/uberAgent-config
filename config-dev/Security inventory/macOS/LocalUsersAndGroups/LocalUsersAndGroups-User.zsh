#
# Security and Compliance Inventory: Local users and groups
#

vlCheckForGuestAccount()
{
  local testName="GuestAccountEnabled"
  local testDisplayName="Guest Account Enabled"
  local testDescription="This test determines if the guest account is enabled. An enabled guest account might be a security risk as it allows unauthorized users to access the system without needing a password, potentially leading to data breaches or other security compromises."
  local testScore=10
  local riskScore=80
  
  local guestAccountEnabled="false"
  local commandReturnValue=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
  if [[ "$commandReturnValue" == "1" ]]; then
    guestAccountEnabled="true"
    testScore=2
  fi
  
  resultData=$(vlAddResultValue "{}" "Guest Account Enabled" "$guestAccountEnabled")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckLocalUserIsAdmin()
{
  local testName="LUUIsAdmin"
  local testDisplayName="Local user is admin"
  local testDescription="Windows: This test determines whether the local user is a member of the local Administrators group. macOS: This test determines if the current user is a member of the group 'admin'."
  local testScore=10
  local riskScore=60

  # Get the username of the user who initially logged in
  local originalUser=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ && ! /loginwindow/ { print $3 }')

  local isUserAdmin="false"
  # Check if the initially logged-in user belongs to the admin group
  if groups $originalUser | grep -q -w admin; then
    isUserAdmin="true"
    testScore=4
  fi
  
  resultData=$(vlAddResultValue "{}" "IsLocalAdmin" "$isUserAdmin")
  resultData=$(vlAddResultValue "$resultData" "Username" "$originalUser")  
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckRootUserEnabled()
{
  local testName="RootUserEnabled"
  local testDisplayName="Root User Enabled"
  local testDescription="Determines if the root user is enabled. This user is a superuser with unrestricted access to the entire operating system and its files. Enabling it poses a security risk as it could potentially allow complete system control if accessed by unauthorized users or malicious software."
  local testScore=10
  local riskScore=100

  local rootStatus=$(dscl . -read /Users/root Password 2>/dev/null)
  local isRootEnabled="false"
  if [[ "$rootStatus" != "Password: *" ]]; then
    isRootEnabled="true"
    testScore=0
  fi
  
  resultData=$(vlAddResultValue "{}" "Root user enabled" "$isRootEnabled")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()
results+="$( vlCheckForGuestAccount )"
results+="$( vlCheckLocalUserIsAdmin )"
results+="$( vlCheckRootUserEnabled )"
# Print the results as JSON
vlPrintJsonReport "${results[@]}"