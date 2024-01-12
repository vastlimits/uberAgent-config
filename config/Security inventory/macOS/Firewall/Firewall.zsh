#
# Security and Compliance Inventory: Firewall Tests
#

vlCheckIsFirewallEnabled()
{
  local riskScore=100
  local expectedOutput="enabled"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "FWState" \
    "macOS Firewall enabled" \
    "Checks whether the macOS firewall is enabled." \
    "$riskScore" \
    "$expectedOutput" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
}

vlCheckIsFirewallBlockallRuleEnabled()
{
  local riskScore=70
  local expectedOutput="Firewall is set to block all non-essential incoming connections"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "FWBlockAll" \
    "macOS Firewall block-all rule active" \
    "Checks whether the block-all rule of the macOS firewall is active." \
    "$riskScore" \
    "$expectedOutput" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
}

vlCheckIsFirewallStealthModeEnabled()
{
  local riskScore=80
  local expectedOutput="enabled"

  vlCheckIsFeatureEnabledFromCommandOutput \
    "FWStealthMode" \
    "macOS Firewall stealth mode active" \
    "Checks whether the stealth mode of the macOS firewall is active." \
    "$riskScore" \
    "$expectedOutput" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
}

vlGetFirewallApprovedApps()
{
  local testName="FWApprovedApps"
  local testDisplayName="macOS Firewall approved applications"
  local testDescription="Provides a list of applications that may accept incoming connections."
  # This test is only informational and always returns a fixed test score
  local testScore=10
  local riskScore=0

  vlRunCommand /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
  if (( $vlCommandStatus != 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$vlCommandStatus" \
      "$vlCommandStderr"
    return
  fi

  local approvedApps=()
  printf "$vlCommandStdout" | \
    grep -B1 '( Allow incoming connections )' | \
    awk '/^[0-9]* *:/' | \
    sed 's/^[0-9]* *: *//' | \
    sed 's/[ \t]*$//' | while IFS= read -r appPath
  do
    approvedApps+=$( "$JQ" $JQFLAGS -n --arg appPath "$appPath" '$appPath' )
  done

  local approvedAppsJson=$( printf '%s\n' "${approvedApps[@]}" | "$JQ" $JQFLAGS -s '{ ApprovedApplications: . }' )
  local approvedAppsEmbeddableJson=$( vlJsonifyEmbeddedJson "$approvedAppsJson" )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$approvedAppsEmbeddableJson"
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$( realpath "$( dirname $0 )/.." )/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()

results+="$( vlCheckIsFirewallEnabled )"
results+="$( vlCheckIsFirewallBlockallRuleEnabled )"
results+="$( vlCheckIsFirewallStealthModeEnabled )"
results+="$( vlGetFirewallApprovedApps )"

vlPrintJsonReport "${results[@]}"
