#
# Security and Compliance Inventory: Utility Functions
#

# Runs "$@" in a subshell with the caller's options, sets reply=(stdout stderr)
# and returns the status of the executed command. Both stdout and stderr are
# captured completely, including NUL bytes, incomplete UTF-8 characters and
# trailing LF, if any.
#
# Taken from: https://gist.github.com/romkatv/605b8ae4499458565e13f715abbd2636
zsh_run_command()
{
  'builtin' 'local' '__zrc'
  __zrc="$(
    __zrc="$( ("$@") || __zrc="$?"; 'builtin' 'printf' '%3d' "$__zrc")" 2>&1 ||
      'builtin' 'printf' '-v' '__zrc' '%3d' "$?"
    'builtin' 'unsetopt' 'multibyte'
    'builtin' 'printf' '%s%18d' "$__zrc" "${#__zrc}"
  )" || 'builtin' 'printf' '-v' '__zrc' '%3d%18d' "$?" '3'
  'builtin' 'emulate' '-L' 'zsh' '-o' 'no_multibyte'
  'builtin' 'local' '-i' n='__zrc[-18,-1]'
  'builtin' 'typeset' '-ga' 'reply'
  'builtin' 'set' '-A' 'reply' "$__zrc[-n-18,-22]" "$__zrc[1,-n-19]"
  'builtin' 'return' '__zrc[-21,-19]'
}

# Wrapper function for zsh_run_command(), making it easier to access the return
# values from the command execution.
#
# Returns the following variables:
#   $?                              The status code from the command execution.
#   sci_util_run_command_status     The status code from the command execution.
#   sci_util_run_command_stdout     The command's stdout.
#   sci_util_run_command_stderr     The command's stderr.
sci_util_run_command()
{
    local __zrc
    zsh_run_command "$@"
    __zrc="$?"
    sci_util_run_command_status="${__zrc}"
    sci_util_run_command_stdout="${reply[1]}"
    sci_util_run_command_stderr="${reply[2]}"
    return __zrc
}

sci_util_jsonify_nullable_string()
{
    local val="$1"

    if [[ -z "$val" ]]; then
        jq -M -n 'null'
    else
        if jq -M -e . >/dev/null 2>&1 <<<"$val"; then
            # If val is valid JSON, convert it into a properly escaped string
            jq -M -n --argjson val "$val" '$val | @json'
        else
            # If val is not valid JSON, encode it as a string
            jq -M -n --arg val "$val" '$val'
        fi
    fi
}

sci_util_report_results_json()
{
    local name="$1"
    local display_name="$2"
    local description="$3"
    local score="$4"
    local risk_score="$5"
    local result_data=$( sci_util_jsonify_nullable_string "$6" )

    jq -n -M --arg name "$name" \
        --arg display_name "$display_name" \
        --arg description "$description" \
        --argjson score "$score" \
        --argjson risk_score "$risk_score" \
        --argjson result_data "$result_data" \
        '{ Name: $name, DisplayName: $display_name, Description: $description, Score: $score, RiskScore: $risk_score, ResultData: $result_data }'
}

sci_util_report_error_json()
{
    local name="$1"
    local display_name="$2"
    local description="$3"
    local error_code="$4"
    # trim whitespace
    local error_msg=$( printf "$5" | awk '{$1=$1};1' )

    jq -n -M --arg name "$name" \
        --argjson error_code "$error_code" \
        --arg display_name "$display_name" \
        --arg description "$description" \
        --arg error_msg "$error_msg" \
        '{ Name: $name, DisplayName: $display_name, Description: $description, ErrorCode: $error_code, ErrorMessage: $error_msg }'
}

sci_util_print_json_report()
{
  printf '%s\n' "${@}" | jq -s -M '.'
}

# Get the minimum test score based on the risk score.
sci_util_get_min_score()
{
  local risk_score="$1"

  if (( $risk_score < 0 )); then
    risk_score=0
  elif (( $risk_score > 100 )); then
    risk_score=100
  fi

  # The result is written to stdout to allow capturing it with $( )
  local min_score=$(( 10 - ( $risk_score / 10 ) ))
  printf "%d" $min_score
}

#
# The following functions run a test consisting by executing a command and expecting an output.
# In sci_util_run_test_expect_match(), the output is expected to match a string exactly.
# In sci_util_run_test_expect_non_match(), the output is expected to not match a string.
#
# The test score is calculated from the risk score based on the expectation.
#
# The last parameter(s) passed to the test comprise the command line to be executed.
# Do not quote this parameter!
#
# e.g.:
#   sci_util_run_test_expected_output "setting on" "80" "enabled" /usr/local/setting --query-setting-on
#
# The result, either success or failured, is printed as JSON to stdout.
#

sci_util_run_test_expect_match()
{
  local test_name="$1"
  local display_name="$2"
  local description="$3"
  local risk_score="$4"
  local expected_output="$5"

  shift 5

  sci_util_run_command $@
  if (( $sci_util_run_command_status != 0 )); then
    sci_util_report_error_json "$test_name" "$display_name" "$description" "$sci_util_run_command_status" "$sci_util_run_command_stderr"
    return
  fi

  printf "$sci_util_run_command_stdout" | grep "$expected_output" >/dev/null 2>&1

  local grep_status=$?
  if (( $grep_status > 1 )); then
    sci_util_report_error_json "$test_name" "$display_name" "$description" "$grep_status" "Interal test error: pattern matching failed."
    return
  fi

  local test_score
  if (( $grep_status == 0 )); then
    test_score=10
  else
    test_score=$( sci_util_get_min_score "$risk_score" )
  fi

  sci_util_report_results_json "$test_name" "$display_name" "$description" "$test_score" "$risk_score"
}

sci_util_run_test_expect_non_match()
{
  local test_name="$1"
  local display_name="$2"
  local description="$3"
  local risk_score="$4"
  local expected_output="$5"

  shift 5

  sci_util_run_command $@
  if (( $sci_util_run_command_status != 0 )); then
    sci_util_report_error_json "$test_name" "$display_name" "$description" "$sci_util_run_command_status" "$sci_util_run_command_stderr"
    return
  fi

  printf "$sci_util_run_command_stdout" | grep "$expected_output" >/dev/null 2>&1

  local grep_status=$?
  if (( $grep_status > 1 )); then
    sci_util_report_error_json "$test_name" "$display_name" "$description" "$grep_status" "Interal test error: pattern matching failed."
    return
  fi

  local test_score
  if (( $grep_status == 1 )); then
    test_score=10
  else
    test_score=$( sci_util_get_min_score "$risk_score" )
  fi

  sci_util_report_results_json "$test_name" "$display_name" "$description" "$test_score" "$risk_score"
}
