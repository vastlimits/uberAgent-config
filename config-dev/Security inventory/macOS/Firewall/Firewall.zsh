#
# Security and Compliance Inventory: Firewall Tests
#

vlCheckIsFirewallEnabled()
{
  local testName="FWState"
  local testDisplayName="Firewall status"
  local testDescription="Windows: This test verifies whether the Windows Defender Firewall is enabled or disabled. It also provides the current connection status of the network profiles. Network profiles allow the system to apply different firewall settings based on the network location, such as a public Wi-Fi network (Public), a corporate network (Domain), or a home network (Private).\nmacOS: Checks whether the macOS firewall is enabled."
  local riskScore=100

  local expectedOutput="enabled"
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
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
}

vlCheckIsFirewallBlockallRuleEnabled()
{
  local testName="FWBlockAll"
  local testDisplayName="macOS block-all rule"
  local testDescription="The block-all rule of the macOS firewall is a setting that restricts all incoming connections, providing an essential layer of security by minimizing potential entry points for threats. This test checks whether this rule is active."
  local riskScore=70
  local expectedOutput="Firewall is set to block all non-essential incoming connections"

  local expectedOutput="enabled"
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
    /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
}

vlCheckIsFirewallStealthModeEnabled()
{
  local testName="FWStealthMode"
  local testDisplayName="macOS stealth mode"
  local testDescription="Stealth mode is a feature that prevents the system from responding to network test requests. Checks whether the stealth mode of the macOS firewall is active."
  local riskScore=80

  local expectedOutput="enabled"
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
    /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
}

vlGetFirewallApprovedApps()
{
  local testName="FWApprovedApps"
  local testDisplayName="macOS approved applications"
  local testDescription="Provides a list of applications that may accept incoming connections. This test is only informational and always returns a fixed test score."
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

  local resultData=$(vlAddResultValue "{}" "ApprovedApplications" '[]')

  printf "$vlCommandStdout" | \
    grep -B1 '( Allow incoming connections )' | \
    awk '/^[0-9]* *:/' | \
    sed 's/^[0-9]* *: *//' | \
    awk '{$1=$1};1' | \
  while IFS= read -r appPath
  do
    resultData=$(vlAddResultValue "$resultData" "ApprovedApplications" "[\"$appPath\"]")
  done

  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()

results+="$( vlCheckIsFirewallEnabled )"
results+="$( vlCheckIsFirewallBlockallRuleEnabled )"
results+="$( vlCheckIsFirewallStealthModeEnabled )"
results+="$( vlGetFirewallApprovedApps )"

vlPrintJsonReport "${results[@]}"
