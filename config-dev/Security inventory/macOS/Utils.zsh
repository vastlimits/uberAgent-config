#
# Security and Compliance Inventory: Utility Functions
#

# Call this function to initialize the variables required to run the utilities
vlInit()
{
  JQ="/Library/uberAgent/uberAgent.app/Contents/MacOS/jq-universal"
  JQFLAGS="-M"

  if [ ! -x "$JQ" ]; then
    printf "Error: Unable to find the JSON processor jq(1) which is required to run this program.\n" 1>&2
    exit 2
  fi
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

# Function to add a key value based attribute to the given json string. Supports nested paths.
# The parameters for vlAddResultValue are: $resultData, $key, $value
#  $resultData should be passed from call to call and contains the result object, if empty a new result object will be created
#  $key is the key of the value you want to add
#  $value is the value you want to add
# For examples have a look at Examples/Template.zsh
vlAddResultValue() {
    local json=$1
    local path=$2
    local value=$3

    shift 3

    # Helper function for JQ command
    jq_command() {
        local type=$1
        local path=$2
        local value=$3
        case $type in
            number | boolean)
                echo "$json" | "$JQ" $JQFLAGS -c --arg path "$path" --argjson value $value '
                    setpath($path | split(".") | map(if test("^[0-9]+$") then tonumber else . end); $value)'
                ;;
            array)
                echo "$json" | "$JQ" $JQFLAGS -c --arg path "$path" --argjson value "$value" '
                    getpath($path | split(".") | map(if test("^[0-9]+$") then tonumber else . end)) += $value'
                ;;
            string)
                echo "$json" | "$JQ" $JQFLAGS -c --arg path "$path" --arg value "$value" '
                    setpath($path | split(".") | map(if test("^[0-9]+$") then tonumber else . end); $value)'
                ;;
        esac
    }

    # Determine the type of the value and call the helper function
    if [[ $value =~ ^[0-9]+$ ]]; then
        jq_command number "$path" $value
    elif [[ $value == "true" || $value == "false" ]]; then
        local boolValue=$(echo "$value" | "$JQ" $JQFLAGS -c .)
        jq_command boolean "$path" $boolValue
    elif [[ $value == \[*\] ]]; then
        jq_command array "$path" "$value"
    else
        jq_command string "$path" "$value"
    fi
}

# Reports the result for an SCI in JSON format.
vlCreateResultObject() {
    local testName="$1"
    local testDisplayName="$2"
    local testDescription="$3"
    local testScore="$4"  # Assuming this is a numeric value
    local riskScore="$5"  # Assuming this is a numeric value
    local resultData="$6"

    shift 6

    "$JQ" $JQFLAGS -c -n \
        --arg name "$testName" \
        --arg displayName "$testDisplayName" \
        --arg description "$testDescription" \
        --argjson score "$testScore" \
        --argjson riskScore "$riskScore" \
        --arg resultData "$resultData" \
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

  shift 1

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
  local testResultVarName="$8"

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

  local resultData=$(vlAddResultValue "{}" "$testResultVarName" $testResultDataValue)

  vlCreateResultObject \
    "$testName" \
    "$displayName" \
    "$description" \
    "$testScore" \
    "$riskScore" \
    "$resultData"
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

  local resultData=$(vlAddResultValue "{}" "Enabled" $testResultDataValue)

  vlCreateResultObject \
    "$testName" \
    "$displayName" \
    "$description" \
    "$testScore" \
    "$riskScore" \
    "$resultData"
}