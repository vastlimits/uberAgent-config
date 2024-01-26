#
# Security and Compliance Inventory: Remote Login
#

vlCheckRemoteLoginDisabled()
{
  local testName="SSHLoginDisabled"
  local testDisplayName="macOS Remote login disabled"
  local testDescription="Checks whether remote login over ssh is disabled."
  local riskScore=40
  local expectedOutput="Remote Login: Off"

  vlCheckIsFeatureDisabledFromCommandOutput \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$riskScore" \
    "$expectedOutput" \
    systemsetup -getremotelogin
}

vlCheckRootUserDisabled()
{
  local testName="SSHRootUserDisabled"
  local testDisplayName="macOS Root user disabled"
  local testDescription="Checks whether the macOS root user is disabled."
  local riskScore=60
  local dontMatchOutput="ShadowHashData"

  vlCheckIsFeatureDisabledFromNonMatchingCommandOutput \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$riskScore" \
    "$dontMatchOutput" \
    plutil -p /var/db/dslocal/nodes/Default/users/root.plist
}

# Sort the comma-separated ssh option values so that they can be matched using
# regular string comparison.
vlGetComparableOptionString()
{
  local options="$1"

  printf "$options" | tr -d '[:blank:]' | tr "," "\n" | sort | tr "\n" "," | sed 's/,$/\n/'
}

vlEnsureValidSshdConfig()
{
  local testName="$1"
  local testDisplayName="$2"
  local testDescription="$3"

  if (( $SSHCONFIGSTATUS == 0 )) && [ -n "$SSHEFFECTIVECONFIG" ]; then
    return 0
  fi

  vlReportErrorJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    128 \
    "Unable to get the sshd effective configuration."

  return 1
}

# This function relies on the global variable ${SSHEFFECTIVECONFIG} being set.
vlGetSshdConfigOpt()
{
  local configOpt="$1"
  local testName="$2"
  local testDisplayName="$3"
  local testDescription="$4"

  local configOptValue=$( printf "${SSHEFFECTIVECONFIG}\n" | grep -i "$configOpt" | awk '{ print $2 }' )
  if [ -z "$configOptValue" ]; then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      1 \
      "Unable to find the sshd $configOpt configuration option."
    return
  fi

  printf $( vlGetComparableOptionString "$configOptValue" )
}

vlCheckSshPasswordLoginDisabled()
{
  local testName="SSHPasswordLoginDisabled"
  local testDisplayName="macOS Remote password login disabled"
  local testDescription="Checks whether remote password logins are disabled on macOS."
  local riskScore=50

  vlEnsureValidSshdConfig "$testName" "$testDisplayName" "$testDescription" || return

  local passwordConfigOpt=$(
    vlGetSshdConfigOpt "passwordauthentication" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$passwordConfigOpt" ] || return

  local testScore=10
  local isDisabled=true
  if [ "$passwordConfigOpt" = "yes" ]; then
    testScore=$( vlGetMinScore "$riskScore" )
    isDisabled=false
  fi

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      "$JQ" $JQFLAGS -n -c \
        --argjson isDisabled $isDisabled \
        '{ Disabled: $isDisabled }' \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}

vlCheckSshFipsCompliant()
{
  local testName="SSHFipsCompliantConfig"
  local testDisplayName="macOS Remote login configuration is FIPS compliant"
  local testDescription="Checks whether the remote login configuration is FIPS compliant."
  local riskScore=60

  vlEnsureValidSshdConfig "$testName" "$testDisplayName" "$testDescription" || return

  local ciphers=$(
    vlGetSshdConfigOpt "Ciphers" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$ciphers" ] || return

  local hostAcceptedAlgos=$(
    vlGetSshdConfigOpt "HostbasedAcceptedAlgorithms" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$hostAcceptedAlgos" ] || return

  local hostKeyAlgos=$(
    vlGetSshdConfigOpt "HostKeyAlgorithms" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$hostKeyAlgos" ] || return

  local kexAlgos=$(
    vlGetSshdConfigOpt "KexAlgorithms" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$kexAlgos" ] || return

  local macs=$(
    vlGetSshdConfigOpt "MACs" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$macs" ] || return

  local pubkeyAcceptedAlgos=$(
    vlGetSshdConfigOpt "PubkeyAcceptedAlgorithms" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$pubkeyAcceptedAlgos" ] || return

  local caAlgos=$(
    vlGetSshdConfigOpt "CASignatureAlgorithms" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$caAlgos" ] || return

  # see appleSshAndFips(7)
  local isFipsCompliant=false
  local testScore=$( vlGetMinScore "$riskScore" )
  if [ "$ciphers" = "aes128-gcm@openssh.com" \
    -a "$hostAcceptedAlgos" = "$( vlGetComparableOptionString ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com )" \
    -a "$hostKeyAlgos" = "$( vlGetComparableOptionString ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com )" \
    -a "$kexAlgos" = "ecdh-sha2-nistp256" \
    -a "$macs" = "hmac-sha2-256" \
    -a "$pubkeyAcceptedAlgos" = "$( vlGetComparableOptionString ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com )" \
    -a "$caAlgos" = "ecdsa-sha2-nistp256" ]
  then
    isFipsCompliant=true
    testScore=10
  fi

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      "$JQ" $JQFLAGS -n -c \
        --argjson isFipsCompliant "$isFipsCompliant" \
        '{ IsFipsCompliant: $isFipsCompliant }' \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}

# Returns the comma-separated values in inputString that match a value in expectedString.
# If any value in inputString is not in expectedString, the function fails.
vlGetMatchingValuesAndRejectNonMatching()
{
  local inputString=$1
  local expectedString=$2
  local inputValues=(${(s/,/)inputString})
  local expectedValues=(${(s/,/)expectedString})
  local matchedValues

  for inputValue in "${inputValues[@]}"; do
    local valueExists=0
    for expectedValue in "${expectedValues[@]}"; do
      if [[ $inputValue == $expectedValue ]]; then
        matchedValues+="${inputValue},"
        valueExists=1
        break
      fi
    done

    if (( valueExists == 0 )); then
      return 1
    fi
  done

  printf "%s\n" $( printf "%s\n" "$matchedValues" | sed 's/,$//g' )
  return 0
}

vlGetTestScoreOnMatchingValues()
{
  local matches=$1
  local expectedString=$2
  local riskScore=$3

  local matchingValues=(${(s/,/)matches})
  local expectedValues=(${(s/,/)expectedString})

  local minScore=$( vlGetMinScore $riskScore )
  local testScore=$( printf "scale=2; ($minScore + ((10 - $minScore) * ${#matchingValues} / ${#expectedValues}))" | bc )
  ## This unusual construction is required for bc to round the score as one would expect.
  local roundedTestScore=$( printf "scale=2; ($testScore + 0.5)/1" | bc )

  printf "%d" $roundedTestScore
}

vlCheckKeysStrongEncryption()
{
  local testName="SSHKeysUseStrongEncryption"
  local testDisplayName="macOS Remote login keys use strong encryption"
  local testDescription="Checks whether the symmetric key algorithms that are used for remote login are strong."
  local riskScore=100

  vlEnsureValidSshdConfig "$testName" "$testDisplayName" "$testDescription" || return

  local kexAlgos=$( \
    vlGetSshdConfigOpt "KexAlgorithms" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$kexAlgos" ] || return

  ## see https://infosec.mozilla.org/guidelines/openssh
  local expectedAlgos="curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"

  local matchingAlgosList=$( \
    vlGetMatchingValuesAndRejectNonMatching \
      "$kexAlgos" \
      "$expectedAlgos" \
    )

  local testScore=$( \
    vlGetTestScoreOnMatchingValues \
      "$matchingAlgosList" \
      "$expectedAlgos" \
      "$riskScore" \
    )

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      tr -d '\n' <<<"$matchingAlgosList" | \
        "$JQ" -R -s -c '{KexAlgorithms: split(",")}' \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}

vlCheckCiphersStrongEncryption()
{
  local testName="SSHCiphersUseStrongEncryption"
  local testDisplayName="macOS Remote login ciphers use strong encryption"
  local testDescription="Checks whether the cipher algorithms that are used for remote login are strong."
  local riskScore=100

  vlEnsureValidSshdConfig "$testName" "$testDisplayName" "$testDescription" || return

  local ciphers=$( \
    vlGetSshdConfigOpt "Ciphers" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$ciphers" ] || return

  ## see https://infosec.mozilla.org/guidelines/openssh
  local expectedCiphers="curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"

  local matchingCiphersList=$( \
    vlGetMatchingValuesAndRejectNonMatching \
      "$ciphers" \
      "$expectedCiphers" \
    )

  local testScore=$( \
    vlGetTestScoreOnMatchingValues \
      "$matchingCiphersList" \
      "$expectedCiphers" \
      "$riskScore" \
    )

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      tr -d '\n' <<<"$matchingCiphersList" | \
        "$JQ" -R -s -c '{Ciphers: split(",")}' \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}

vlCheckMacsStrongEncryption()
{
  local testName="SSHMacsUseStrongEncryption"
  local testDisplayName="macOS Remote login MACs use strong encryption"
  local testDescription="Checks whether the MAC algorithms that are used for remote login are strong."
  local riskScore=100

  vlEnsureValidSshdConfig "$testName" "$testDisplayName" "$testDescription" || return

  local macs=$( \
    vlGetSshdConfigOpt "MACs" \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" )
  [ -n "$macs" ] || return

  local testScore=$( vlGetMinScore "$riskScore" )

  ## see https://infosec.mozilla.org/guidelines/openssh
  local expectedMacs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"

  local matchingMacsList=$( \
    vlGetMatchingValuesAndRejectNonMatching \
      "$macs" \
      "$expectedMacs" \
    )

  local testScore=$( \
    vlGetTestScoreOnMatchingValues \
      "$matchingMacsList" \
      "$expectedMacs" \
      "$riskScore" \
    )

  local resultDataJson=$( \
    vlJsonifyEmbeddedJson $( \
      tr -d '\n' <<<"$matchingMacsList" | \
        "$JQ" -R -s -c '{MACs: split(",")}' \
    ) \
  )

  vlReportTestResultJson \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultDataJson"
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()

results+="$( vlCheckRemoteLoginDisabled )"
results+="$( vlCheckRootUserDisabled )"

# The sshd configuration is required for the next tests
vlRunCommand sshd -T
SSHCONFIGSTATUS="$vlCommandStatus"
SSHEFFECTIVECONFIG="$vlCommandStdout"

results+="$( vlCheckSshPasswordLoginDisabled )"
results+="$( vlCheckSshFipsCompliant )"
results+="$( vlCheckKeysStrongEncryption )"
results+="$( vlCheckCiphersStrongEncryption )"
results+="$( vlCheckMacsStrongEncryption )"

vlPrintJsonReport "${results[@]}"
