#
# Security and Compliance Inventory: Utility Functions
#

# Call this function to initialize the variables required to run the utilities
vlInit()
{
  ## This logic to use either version of jq is provided only for testing the scripts
  ## FIXME: Remove this logic before releasing
  local uberAgentJq="/Library/uberAgent/uberAgent.app/Contents/MacOS/jq-universal"
  local systemJq=$( which jq )

  if [ -x "$uberAgentJq" ]; then
    JQ="$uberAgentJq"
  elif [ -x "$systemJq" ]; then
    JQ="$systemJq"
  else
    printf "Error: Unable to find the JSON processor jq(1) which is required to run this program.\n" 1>&2
    exit 2
  fi

  JQFLAGS="-M"
}

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
#   $?                  The status code from the command execution.
#   vlCommandStatus     The status code from the command execution.
#   vlCommandStdout     The command's stdout.
#   vlCommandStderr     The command's stderr.
vlRunCommand()
{
    local __zrc
    zsh_run_command "$@"
    __zrc="$?"
    vlCommandStatus="${__zrc}"
    vlCommandStdout="${reply[1]}"
    vlCommandStderr="${reply[2]}"
    return __zrc
}

# Encodes JSON to be included embedded as an attribute within another JSON document
vlJsonifyEmbeddedJson()
{
  local val="$1"
  "$JQ" $JQFLAGS -n --argjson val "$val" '$val | @json'
}

# Reports the result for an SCI in JSON format.
# Assumes that the ResultData field is a JSON object.
vlReportTestResultJson()
{
    local name="$1"
    local displayName="$2"
    local description="$3"
    local score="$4"
    local riskScore="$5"
    local resultData="$6"

    # NOTE: we pass the resultData parameter as argjson so that it is interpreted
    # as JSON data and not as a string.
    "$JQ" $JQFLAGS -n \
        --arg name "$name" \
        --arg displayName "$displayName" \
        --arg description "$description" \
        --argjson score "$score" \
        --argjson riskScore "$riskScore" \
        --argjson resultData "$resultData" \
        $'{ Name: $name, \
            DisplayName: $displayName, \
            Description: $description, \
            Score: $score, \
            RiskScore: $riskScore, \
            ResultData: $resultData \
          }'
}

vlReportErrorJson()
{
    local name="$1"
    local displayName="$2"
    local description="$3"
    local errorCode="$4"
    local errorMsg=$( printf "$5" | awk '{$1=$1};1' ) # trim whitespace

    "$JQ" $JQFLAGS -n \
        --arg name "$name" \
        --argjson errorCode "$errorCode" \
        --arg displayName "$displayName" \
        --arg description "$description" \
        --arg errorMsg "$errorMsg" \
        $'{ Name: $name, \
            DisplayName: $displayName, \
            Description: $description, \
            ErrorCode: $errorCode, \
            ErrorMessage: $errorMsg \
          }'
}

vlPrintJsonReport()
{
  printf '%s\n' "${@}" | "$JQ" $JQFLAGS -s '.'
}

# Get the minimum test score based on the risk score.
vlGetMinScore()
{
  local riskScore="$1"

  if (( $riskScore < 0 )); then
    riskScore=0
  elif (( $riskScore > 100 )); then
    riskScore=100
  fi

  # The result is written to stdout to allow capturing it with $( )
  local minScore=$(( 10 - ( $riskScore / 10 ) ))
  printf "%d" $minScore
}

#
# vlCheckIsFeatureEnabledFromCommandOutput - check whether a feature is enabled from a command's output
#
# This function runs the command specified as the last argument(s) and matches its output with the specified
# expectedOutput parameter.
# Do not quote the command invocation parameters!
#
# If the expectedOutput is found, the feature is considered enabled. Otherwise the feature is disabled.
# Errors are reported using the appropriate JSON schema.
#
# The output of this function includes a ResultData field:
#    "ResultData": {
#      "Enabled": true/false
#    }
#
vlCheckIsFeatureEnabledFromCommandOutput()
{
  local testName="$1"
  local displayName="$2"
  local description="$3"
  local riskScore="$4"
  local expectedOutput="$5"

  shift 5

  vlRunCommand $@
  if (( $vlCommandStatus != 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$displayName" \
      "$description" \
      "$vlCommandStatus" \
      "$vlCommandStderr"
    return
  fi

  printf "$vlCommandStdout" | grep "$expectedOutput" >/dev/null 2>&1
  local grepStatus=$?
  if (( $grepStatus > 1 )); then
    vlReportErrorJson \
      "$testName" \
      "$displayName" \
      "$description" \
      "$grepStatus" \
      "Interal test error: pattern matching failed."
    return
  fi

  # initialize with the negative case, and modify if the matching condition is met
  local testScore=$( vlGetMinScore "$riskScore" )
  local testResultDataValue=false

  if (( $grepStatus == 0 )); then
    # the matching string was found
    testScore=10
    testResultDataValue=true
  fi

  local resultDataJson=$( "$JQ" $JQFLAGS -n -c \
                        --argjson testResultDataValue \
                        "$testResultDataValue" '{ Enabled: $testResultDataValue }' )

  vlReportTestResultJson \
    "$testName" \
    "$displayName" \
    "$description" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}
