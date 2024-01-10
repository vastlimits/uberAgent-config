#
# Security and Compliance Inventory: Firewall Tests
#

# Include the sci_util_* functions
SCRIPT_DIR="$( dirname "$0" )"
SCI_UTILS_DIR=$( printf '%s/..' "$SCRIPT_DIR" )
. "$SCI_UTILS_DIR/Utils.zsh"

sci_test_firewall_enabled()
{
  local risk_score=100
  local expected_output="enabled"

  ## TODO: review: use "active" or "enabled"? Ensure consistent verbs with the Windows version as well!
  sci_util_run_test_expect_match \
    "FWEnabled" \
    "Firewall enabled" \
    "Checks whether the macOS firewall is enabled." \
    "$risk_score" \
    "$expected_output" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
}

sci_test_firewall_blockall_enabled()
{
  local risk_score=70
  local expected_output="enabled"

  ## TODO: review: use "active" or "enabled"? Ensure consistent verbs with the Windows version as well!
  sci_util_run_test_expect_match \
    "FWBlockAll" \
    "Firewall block-all rule active" \
    "Checks whether the block-all rule of the macOS firewall is active." \
    "$risk_score" \
    "$expected_output" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
}

sci_test_firewall_stealth_mode_enabled()
{
  local risk_score=80
  local expected_output="enabled"

  ## TODO: review: use "active" or "enabled"? Ensure consistent verbs with the Windows version as well!
  sci_util_run_test_expect_match \
    "FWStealthMode" \
    "Firewall stealth mode active" \
    "Checks whether the stealth mode of the macOS firewall is active." \
    "$risk_score" \
    "$expected_output" \
    /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
}

sci_test_firewall_approved_apps()
{
  local test_name="FWApprovedApps"
  local test_display_name="Firewall approved applications"
  local test_description="Provides a list of applications that may accept incoming connections."
  # This test is only informational and always returns a fixed test score
  local test_score=10
  local risk_score=0

  sci_util_run_command /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
  if (( $sci_util_run_command_status != 0 )); then
    sci_util_report_error_json \
      "$test_name" \
      "$test_display_name" \
      "$test_description" \
      "$sci_util_run_command_status" \
      "$sci_util_run_command_stderr"
    return
  fi

  local approved_apps=()
  printf "$sci_util_run_command_stdout" | \
    grep -B1 '( Allow incoming connections )' | \
    awk '/^[0-9]* *:/' | \
    sed 's/^[0-9]* *: *//' | \
    sed 's/[ \t]*$//' | while IFS= read -r app_path
  do
    approved_apps+=$( jq -M -n --arg app_path "$app_path" '$app_path' )
  done

  local approved_apps_json=$( printf '%s\n' "${approved_apps[@]}" | jq -c -s -M '{ ApprovedApplications: . }' )

  sci_util_report_results_json \
    "$test_name" \
    "$test_display_name" \
    "$test_description" \
    "$test_score" \
    "$risk_score" \
    "$approved_apps_json"
}

# Entry point
results=()

results+="$( sci_test_firewall_enabled )"
results+="$( sci_test_firewall_blockall_enabled )"
results+="$( sci_test_firewall_stealth_mode_enabled )"
results+="$( sci_test_firewall_approved_apps )"

sci_util_print_json_report "${results[@]}"
