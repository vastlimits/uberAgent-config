#
# Security and Compliance Inventory: OS Updates Tests
#

vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled()
{
  local testName="SWUAutomaticUpdateCheckingEnabled"
  local testDisplayName="macOS updates"
  local testDescription="Disabling automatic update checks on macOS can leave the system vulnerable to threats. This test verifys if automatic update checks are enabled."
  local riskScore=100

  local expectedOutput="Automatic checking for updates is turned on"
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
    softwareupdate --schedule
}

vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled()
{
  local testName="SWUAutomaticUpdateAppStoreCheckingEnabled"
  local testDisplayName="macOS AppStore updates"
  local testDescription="Deactivating AppStore updates can result in out-of-date applications, increasing the risk of security breaches. This test verifys if AppStore update checks are enabled."
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
  local testDisplayName="macOS recommended updates"
  local testDescription="Provides a list of pending recommended macOS software updates."
  local riskScore=90

  local resultData=$(vlAddResultValue "{}" "RecommendedUpdates" '[]')

  ## The softwareupdate doesn't use return codes to indicate sucess or failure.
  softwareupdate -l 2>/dev/null \
    | grep 'Recommended: YES' | cut -d"," -f1 | cut -d":" -f2 | awk '{$1=$1};1' \
    | while IFS= read -r availableUpdate
  do
    resultData=$(vlAddResultValue "$resultData" "RecommendedUpdates" "[\"$availableUpdate\"]")
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
  local testDisplayName="macOS security response updates"
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
