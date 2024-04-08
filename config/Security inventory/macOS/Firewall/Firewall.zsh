#
# Security and Compliance Inventory: Firewall Tests
#

# Global variables collecting the results for each executed test
scoresForAllTests=()
resultDataForAllTests="{}"


vlCheckIsFirewallEnabled()
{
  local testName="$1"
  local testDisplayName="$2"
  local testDescription="$3"
  local riskScore=100

  vlRunCommand /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
  if (( $vlCommandStatus != 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$vlCommandStatus" \
      "$vlCommandStderr"
    return 2
  fi

  local resultDataPropertyName="FirewallEnabled"
  printf "$vlCommandStdout" | grep "enabled" >/dev/null 2>&1
  case $? in
    0)
      # The firewall is enabled
      scoresForAllTests+=(10)
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "true")
      return 0
      ;;
    1)
      # The firewall is disabled
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "false")

      vlCreateResultObject \
        "$testName" \
        "$testDisplayName" \
        "$testDescription" \
        0 \
        "$riskScore" \
        "$resultDataForAllTests"

      return 1
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
}

vlCheckIsFirewallBlockallRuleEnabled()
{
  local testName="FWBlockAll"
  local testDisplayName="macOS block-all rule"
  local testDescription="The block-all rule of the macOS firewall is a setting that restricts all incoming connections, providing an essential layer of security by minimizing potential entry points for threats. This test checks whether this rule is active."
  local riskScore=70
  local expectedOutput="Firewall is set to block all non-essential incoming connections"

  vlRunCommand /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
  if (( $vlCommandStatus != 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$vlCommandStatus" \
      "$vlCommandStderr"
    return 2
  fi

  local resultDataPropertyName="BlockAllRuleEnabled"
  printf "$vlCommandStdout" | grep "Block all DISABLED" >/dev/null 2>&1
  case $? in
    0)
      # Disabled
      scoresForAllTests+=($( vlGetMinScore "$riskScore" ))
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "false")
      ;;
    1)
      # Enabled
      scoresForAllTests+=(10)
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "true")
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

  return 0
}

vlCheckIsFirewallStealthModeEnabled()
{
  local testName="FWStealthMode"
  local testDisplayName="macOS stealth mode"
  local testDescription="Stealth mode is a feature that prevents the system from responding to network test requests. Checks whether the stealth mode of the macOS firewall is active."
  local riskScore=80

  vlRunCommand /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
  if (( $vlCommandStatus != 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$vlCommandStatus" \
      "$vlCommandStderr"
    return 2
  fi

  local resultDataPropertyName="StealthModeEnabled"
  printf "$vlCommandStdout" | grep "enabled" >/dev/null 2>&1
  case $? in
    0)
      # Enabled
      scoresForAllTests+=(10)
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "true")
      ;;
    1)
      # Disabled
      scoresForAllTests+=($( vlGetMinScore "$riskScore" ))
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "false")
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

  return 0
}

# This test is only informational so it doesn't have a score.
vlGetFirewallApprovedApps()
{
  local testName="FWApprovedApps"
  local testDisplayName="macOS approved applications"
  local testDescription="Provides a list of applications that may accept incoming connections. This test is only informational and always returns a fixed test score."

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

  resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "ApprovedApplications" '[]')

  printf "$vlCommandStdout" | \
    grep -B1 '( Allow incoming connections )' | \
    awk '/^[0-9]* *:/' | \
    sed 's/^[0-9]* *: *//' | \
    awk '{$1=$1};1' | \
  while IFS= read -r appPath
  do
    resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "ApprovedApplications" "[\"$appPath\"]")
  done
}

vlFirewallTests()
{
  local testName="FWState"
  local testDisplayName="Firewall status"
  local testDescription="Windows: This test verifies whether the Windows Defender Firewall is enabled or disabled. It also provides the current connection status of the network profiles. Network profiles allow the system to apply different firewall settings based on the network location, such as a public Wi-Fi network (Public), a corporate network (Domain), or a home network (Private). macOS: performs comprehensive checking of firewall settings. If the firewall is enabled, this test also validates the status of the block-all rule, stealth mode, and a list of approved applications."
  local riskScore=100

  vlCheckIsFirewallEnabled \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    || return $(( $? - 1 ))

  vlCheckIsFirewallBlockallRuleEnabled || return 1
  vlCheckIsFirewallStealthModeEnabled || return 1
  vlGetFirewallApprovedApps || return 1

  # Use the average of all sub scores as the final score.
  local sum=0
  for score in "${scoresForAllTests[@]}"; do
    sum=$((sum + score))
  done

  local testScore=$(echo "$sum / ${#scoresForAllTests[@]}" | bc)

  vlCreateResultObject \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultDataForAllTests"
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Run the tests
results=()
results+="$( vlFirewallTests )"
vlPrintJsonReport "${results[@]}"
