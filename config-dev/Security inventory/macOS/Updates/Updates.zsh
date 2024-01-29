#
# Security and Compliance Inventory: OS Updates Tests
#

vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled()
{
  local testName="SWUAutomaticUpdateCheckingEnabled"
  local testDisplayName="Automatic checking for macOS updates enabled"
  local testDescription="Checks whether the automatic check for macOS updates is enabled."
  local riskScore=100
  local expectedOutput="Automatic checking for updates is turned on"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$riskScore" \
    "$expectedOutput" \
    softwareupdate --schedule
}

vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled()
{
  local testName="SWUAutomaticUpdateAppStoreCheckingEnabled"
  local testDisplayName="Automatic checking for AppStore updates enabled"
  local testDescription="Checks whether the automatic check for AppStore updates is enabled."
  local riskScore=80
  local plistDefault=0

  vlCheckFeatureEnabledFromPlistDomainKey \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$riskScore" \
    "/Library/Preferences/com.apple.commerce" \
    "AutoUpdate" \
    $plistDefault
}

vlCheckForRecommendedUpdates()
{
  local testName="SWURecommendedUpdatesAvailable"
  local testDisplayName="Checks whether there are recommended software updates pending"
  local testDescription="Provides a list of pending recommended software updates."
  local riskScore=90

  local resultData=$(vlAddResultValue "" "RecommendedUpdates" '[]')

  ## The softwareupdate doesn't use return codes to indicate sucess or failure.
  softwareupdate -l 2>/dev/null \
    | grep 'Recommended: YES' | cut -d"," -f1 | cut -d":" -f2 | awk '{$1=$1};1' \
    | while IFS= read -r availableUpdate
  do
    resultData=$(vlAddResultValue "$resultData" "ApprovedApplications" '["$availableUpdate"]')
  done

  local testScore=$( vlGetMinScore "$riskScore" )
  if [ ${#availableRecommendedUpdates[@]} -eq 0 ]; then
    local testScore=10
  fi

  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckInstallSecurityResponsesAndSystemFilesEnabled()
{
  local testName="SWUInstallSecurityResponsesAndSystemFilesEnabled"
  local testDisplayName="Install security responses and system files automatically"
  local testDescription="Checks whether the automatic installation of security responses and system files is enabled."
  local riskScore=80
  local plistDefault=1

  vlCheckFeatureEnabledFromPlistDomainKey \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    $riskScore \
    "/Library/Preferences/com.apple.SoftwareUpdate" \
    "ConfigDataInstall" \
    $plistDefault
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()

results+="$( vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled )"
results+="$( vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled )"
results+="$( vlCheckForRecommendedUpdates )"
results+="$( vlCheckInstallSecurityResponsesAndSystemFilesEnabled )"

vlPrintJsonReport "${results[@]}"
