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
  "$JQ" $JQFLAGS -n -c --arg val "$val" '$val'
}

# This function expects each input strings to be quoted, like: "string"
vlJsonifyArrayJson()
{
  local arrayName="$1"
  shift
  local array=("$@")

  local arrayAsJson=$( printf '%s\n' "${array[@]}" | "$JQ" $JQFLAGS -c -s "{ $arrayName: . }" )
  "$JQ" $JQFLAGS -n --arg val "$arrayAsJson" '$val'
}

# Reports the result for an SCI in JSON format.
# Callers must escape the resultData with vlJsonifyEmbeddedJson(), if it contains JSON data.
vlReportTestResultJson()
{
    local name="$1"
    local displayName="$2"
    local description="$3"
    local score="$4"
    local riskScore="$5"
    local resultData="$6"

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

vlReportTestResultJsonResultDataArray()
{
    local name="$1"
    local displayName="$2"
    local description="$3"
    local score="$4"
    local riskScore="$5"
    local resultDataArrayName="$6"
    shift 6
    local resultDataArray=("$@")

    local resultData=$( vlJsonifyArrayJson "$resultDataArrayName" ${resultDataArray[@]} )

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

vlNegateBooleanValue()
{
  local val="$1"

  if [ "$val" = "true" ]; then
    printf "false"
  elif [ "$val" = "false" ]; then
    printf "true"
  else
    printf "invalid value"
  fi
}

# This is the base function for establishing the current state of a feature
# by running a command and expecting an output.
# The ResultData is also customizable; pass a valid jq template where the
# test result boolean value can be referenced by the $testResultDataValue variable,
# for example:
#   '{ Enabled: $testResultDataValue }'
vlCheckFeatureStateFromCommandOutput()
{
  local testName="$1"
  local displayName="$2"
  local description="$3"
  local riskScore="$4"
  local expectedOutput="$5"
  local expectedGrepStatus="$6"
  local expectedTestResultDataValue="$7"
  local testResultDataJsonTemplate="$8"

  shift 8

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
  local testResultDataValue=$( vlNegateBooleanValue "$expectedTestResultDataValue" )

  if (( $grepStatus == $expectedGrepStatus )); then
    # positive (expected) case
    testScore=10
    testResultDataValue=$( vlNegateBooleanValue "$testResultDataValue" )
  fi

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      "$JQ" $JQFLAGS -n -c \
        --argjson testResultDataValue $testResultDataValue \
        "$testResultDataJsonTemplate" \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$displayName" \
    "$description" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}

# Checks whether a feature is enabled by matching the specified expected output
# from a command.
# If the output matches, then the feature is considered enabled.
# Never quote the command invocation parameters, which must be specified last!
#
# The ResultData field is reported accordingly:
#
#    "ResultData": {
#      "Enabled": true/false
#    }
#
# Errors are reported using the appropriate JSON schema.
vlCheckIsFeatureEnabledFromCommandOutput()
{
  local testName="$1"
  local displayName="$2"
  local description="$3"
  local riskScore="$4"
  local expectedOutput="$5"

  shift 5

  local expectedGrepStatus=0
  local expectedTestResultDataValue=true
  local testResultDataJsonTemplate='{ Enabled: $testResultDataValue }'

  vlCheckFeatureStateFromCommandOutput \
    "$testName" \
    "$displayName" \
    "$description" \
    "$riskScore" \
    "$expectedOutput" \
    "$expectedGrepStatus" \
    "$expectedTestResultDataValue" \
    "$testResultDataJsonTemplate" \
    $@
}

# Checks whether a feature is disabled by matching the specified expected output
# from a command.
# If the output matches, then the feature is considered disabled.
# Never quote the command invocation parameters, which must be specified last!
#
# The ResultData field is reported accordingly:
#
#    "ResultData": {
#      "Disabled": true/false
#    }
#
# Errors are reported using the appropriate JSON schema
vlCheckIsFeatureDisabledFromCommandOutput()
{
  local testName="$1"
  local displayName="$2"
  local description="$3"
  local riskScore="$4"
  local expectedOutput="$5"

  shift 5

  local expectedGrepStatus=0
  local expectedTestResultDataValue=true
  local testResultDataJsonTemplate='{ Disabled: $testResultDataValue }'

  vlCheckFeatureStateFromCommandOutput \
    "$testName" \
    "$displayName" \
    "$description" \
    "$riskScore" \
    "$expectedOutput" \
    "$expectedGrepStatus" \
    "$expectedTestResultDataValue" \
    "$testResultDataJsonTemplate" \
    $@
}

# Checks whether a feature is disabled by ensuring that the output of the specified
# command does NOT match a specific string.
# If the command output doesn't match the string, the feature is considered disabled.
# Never quote the command invocation parameters, which must be specified last!
#
# The ResultData field is reported accordingly:
#
#    "ResultData": {
#      "Disabled": true/false
#    }
#
# Errors are reported using the appropriate JSON schema
vlCheckIsFeatureDisabledFromNonMatchingCommandOutput()
{
  local testName="$1"
  local displayName="$2"
  local description="$3"
  local riskScore="$4"
  local expectedOutput="$5"

  shift 5

  local expectedGrepStatus=1
  local expectedTestResultDataValue=true
  local testResultDataJsonTemplate='{ Disabled: $testResultDataValue }'

  vlCheckFeatureStateFromCommandOutput \
    "$testName" \
    "$displayName" \
    "$description" \
    "$riskScore" \
    "$expectedOutput" \
    "$expectedGrepStatus" \
    "$expectedTestResultDataValue" \
    "$testResultDataJsonTemplate" \
    $@
}

vlCheckFeatureEnabledFromPlistDomainKey()
{
  local testName="$1"
  local displayName="$2"
  local description="$3"
  local riskScore="$4"
  local plistDomain="$5"
  local plistKey="$6"
  local plistDefaultOnMissingKey="$7"

  vlRunCommand defaults read "$plistDomain" "$plistKey"

  # Attempt to read the plist value, but use the default value if the key domain pair is not found
  local plistValue="$plistDefaultOnMissingKey"
  if (( $vlCommandStatus == 0 )); then
    plistValue="$vlCommandStdout"
  fi

  local expectedOutput=1
  printf "$plistValue" | grep "$expectedOutput" >/dev/null 2>&1
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
  local expectedGrepStatus=0
  if (( $grepStatus == $expectedGrepStatus )); then
    # positive (expected) case
    testScore=10
    testResultDataValue=true
  fi

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      "$JQ" $JQFLAGS -n -c \
        --argjson testResultDataValue $testResultDataValue \
        '{ Enabled: $testResultDataValue }' \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$displayName" \
    "$description" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}