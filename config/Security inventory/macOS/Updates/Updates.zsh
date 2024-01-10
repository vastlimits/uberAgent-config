#
# Security and Compliance Inventory: OS Updates Tests
#

vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled()
{
  local riskScore=100
  local expectedOutput="Automatic checking for updates is turned on"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "SWUAutomaticUpdateCheckingEnabled" \
    "Automatic checking for macOS updates enabled" \
    "Checks whether the automatic check for macOS updates is enabled." \
    "$riskScore" \
    "$expectedOutput" \
    softwareupdate --schedule
}

vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled()
{
  local riskScore=80
  local expectedOutput="1"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "SWUAutomaticUpdateAppStoreCheckingEnabled" \
    "Automatic checking for AppStore updates enabled" \
    "Checks whether the automatic check for AppStore updates is enabled." \
    "$riskScore" \
    "$expectedOutput" \
    defaults read /Library/Preferences/com.apple.commerce AutoUpdate
}

vlCheckForRecommendedUpdates()
{
  local testName="SWURecommendedUpdatesAvailable"
  local testDisplayName="Checks whether there are recommended software updates pending"
  local testDescription="Provides a list of pending recommended software updates."
  local riskScore=90

  local availableRecommendedUpdates=()

  ## The softwareupdate doesn't use return codes to indicate sucess or failure.
  softwareupdate -l 2>/dev/null \
    | grep 'Recommended: YES' | cut -d"," -f1 | cut -d":" -f2 | awk '{$1=$1};1' \
    | while IFS= read -r availableUpdate
  do
    availableRecommendedUpdates+=$( "$JQ" $JQFLAGS -n --arg availableUpdate "$availableUpdate" '$availableUpdate' )
  done

  local testScore=$( vlGetMinScore "$riskScore" )
  if [ ${#availableRecommendedUpdates[@]} -eq 0 ]; then
    local testScore=10
  fi

  local availableRecommendedUpdatesJson=$( printf '%s\n' "${availableRecommendedUpdates[@]}" | "$JQ" $JQFLAGS -s '{ RecommendedUpdates: . }' )
  local availableRecommendedUpdatesEmbeddableJson=$( vlJsonifyEmbeddedJson "$availableRecommendedUpdatesJson" )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$availableRecommendedUpdatesEmbeddableJson"
}

vlCheckInstallSecurityResponsesAndSystemFilesEnabled()
{
  local riskScore=80
  local expectedOutput="1"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "SWUInstallSecurityResponsesAndSystemFilesEnabled" \
    "Install security responses and system files automatically" \
    "Checks whether the automatic installation of security responses and system files is enabled." \
    "$riskScore" \
    "$expectedOutput" \
    defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$( realpath "$( dirname $0 )/.." )/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()

results+="$( vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled )"
results+="$( vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled )"
results+="$( vlCheckForRecommendedUpdates )"
results+="$( vlCheckInstallSecurityResponsesAndSystemFilesEnabled )"

vlPrintJsonReport "${results[@]}"
