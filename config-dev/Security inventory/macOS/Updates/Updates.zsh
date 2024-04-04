#
# Security and Compliance Inventory: OS Updates Tests
#

# Global variables collecting the results for each executed test
scoresForAllTests=()
resultDataForAllTests="{}"


vlCheckPlistKey()
{
  local plistDomain="$1"
  local plistKey="$2"
  local plistDefaultOnMissingKey="$3"
  local resultDataPropertyName="$4"
  local riskScore="$5"

  vlRunCommand defaults read "$plistDomain" "$plistKey"

  # Attempt to read the plist value, but use the default value (manually from the UI)
  # if the key domain pair is not found.
  local plistValue="$plistDefaultOnMissingKey"
  if (( $vlCommandStatus == 0 )); then
    plistValue="$vlCommandStdout"
  fi

  if (( plistValue == 1 )); then
    scoresForAllTests+=(10)
    resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "true")
  else
    scoresForAllTests+=( $( vlGetMinScore "$riskScore" ) )
    resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "false")
  fi
}

vlAverageScores()
{
  # Use the average of all sub scores as the final score.
  local sum=0
  for score in "${scoresForAllTests[@]}"; do
    sum=$((sum + score))
  done

  local testScore=$(echo "$sum / ${#scoresForAllTests[@]}" | bc)
  printf "$testScore"
}

vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled()
{
  local testName="SWUAutomaticUpdateCheckingEnabled"
  local testDisplayName="macOS updates"
  local testDescription="Disabling automatic update checks on macOS can leave the system vulnerable to threats. This test verifies that automatic update checks are enabled."
  local riskScore=100

  vlRunCommand softwareupdate --schedule

  # The softwareupdate always returns zero, even on failure.
  if [ -n "$vlCommandStderr" ]; then
    local errorCode=1
    local errorMessage=$( printf "$vlCommandStderr" | head -n1 )
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$errorCode" \
      "$errorMessage"
    return 2
  fi

  local resultDataPropertyName="AutomaticUpdatesEnabled"
  printf "$vlCommandStdout" | grep "Automatic checking for updates is turned on" >/dev/null 2>&1
  case $? in
    0)
      scoresForAllTests+=(10)
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "true")
      ;;
    1)
      scoresForAllTests+=(0)
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "false")

      vlCheckForRecommendedUpdates

      vlCreateResultObject \
        "$testName" \
        "$testDisplayName" \
        "$testDescription" \
        "$( vlAverageScores )" \
        "$riskScore" \
        "$resultDataForAllTests"

      return 0
      ;;
    *)
      vlReportErrorJson \
        "$testName" \
        "$testDisplayName" \
        "$testDescription" \
        "$?" \
        "Internal error: pattern matching failed."
      return 2
      ;;
  esac

  vlCheckPlistKey \
    "/Library/Preferences/com.apple.SoftwareUpdate" \
    "AutomaticDownload" \
    1 \
    "AutomaticDownloadEnabled" \
    80

  vlCheckPlistKey \
    "/Library/Preferences/com.apple.SoftwareUpdate" \
    "AutomaticallyInstallMacOSUpdates" \
    0 \
    "AutomaticaInstallOSUpdatesEnabled" \
    80

  vlCheckPlistKey \
    "/Library/Preferences/com.apple.SoftwareUpdate" \
    "ConfigDataInstall" \
    1 \
    "InstallSecurityResponsesEnabled" \
    100

  vlCheckForRecommendedUpdates

  vlCreateResultObject \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$( vlAverageScores )" \
    "$riskScore" \
    "$resultDataForAllTests"

  return 0
}

vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled()
{
  local testName="SWUAutomaticUpdateAppStoreCheckingEnabled"
  local testDisplayName="macOS AppStore updates"
  local testDescription="Deactivating AppStore updates can result in out-of-date applications, increasing the risk of security breaches. This test verifies if AppStore update checks are enabled."
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

  resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "RecommendedUpdates" '[]')

  local availableRecommendedUpdates=0
  ## The softwareupdate doesn't use return codes to indicate sucess or failure.
  softwareupdate -l 2>/dev/null \
    | grep 'Recommended: YES' | cut -d"," -f1 | cut -d":" -f2 | awk '{$1=$1};1' \
    | while IFS= read -r availableUpdate
  do
    resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "RecommendedUpdates" "[\"$availableUpdate\"]")
    availableRecommendedUpdates=$(( availableRecommendedUpdates + 1 ))
  done

  if (( availableRecommendedUpdates == 0 )); then
    scoresForAllTests+=(10)
  else
    scoresForAllTests+=($( vlGetMinScore "$riskScore" ))
  fi
}

vlUpdatesTests()
{
  vlCheckIsAutomaticCheckingForMacOSUpdatesEnabled || return 1

  vlCheckIsAutomaticCheckingForAppStoreUpdatesEnabled
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()
results+="$( vlUpdatesTests )"
vlPrintJsonReport "${results[@]}"
