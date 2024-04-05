#
# Security and Compliance Inventory: Remote Login
#

# Global variables collecting the results for each executed test
scoresForAllTests=()
resultDataForAllTests="{}"

# Maps sshd configuration options to their respective effective values; see vlLoadSshdConfig()
typeset -A sshdConfiguration


# Sort the comma-separated ssh option values so that they can be matched using
# regular string comparison.
vlGetComparableOptionString()
{
  local options="$1"

  printf "$options" | tr -d '[:blank:]' | tr "," "\n" | sort | tr "\n" "," | sed 's/,$/\n/'
}


# Loads the configuration options passed in as arguments to the global sshdConfiguration map.
vlLoadSshdConfig()
{
  local testName="$1"
  local testDisplayName="$2"
  local testDescription="$3"

  shift 3

  vlRunCommand sshd -T

  local sshConfigStatus="$vlCommandStatus"
  local effectiveSshdConfig="$vlCommandStdout"

  if (( $sshConfigStatus != 0 )) || [ -z "$effectiveSshdConfig" ]; then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      128 \
      "Unable to get the Remote Login configuration (sshd status code: ${sshConfigStatus})"

    return 1
  fi

  local missingConfigOpts=()
  for sshdConfigOptName in $@; do
    local sshdConfigOptValue=$(printf "${effectiveSshdConfig}\n" | grep -i "$sshdConfigOptName" | awk '{ print $2 }')
    if [ -z "$sshdConfigOptValue" ]; then
      missingConfigOpts+="$sshdConfigOptName"
    fi

    sshdConfiguration[$sshdConfigOptName]="$( vlGetComparableOptionString "$sshdConfigOptValue" )"
  done

  if (( ${#missingConfigOpts[@]} > 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      1 \
      "Missing sshd configuration options: ${(j:,:)missingConfigOpts}."

    return 1
  fi

  return 0
}


# If the configuration cannot be loaded even though Remote Login is on
# --which is very unlikely-- an error for the whole test is returned.
# Returns: 0 when sshd is enabled, 1 when disabled and 2 on error.
vlCheckRemoteLoginEnabled()
{
  local testName="SSHLoginDisabled"
  local displayName="macOS remote login"
  local description="Turning off remote login over SSH eliminates an access point that could potentially be exploited, increasing system security. Checks whether remote login over ssh is disabled."
  local expectedOutput="Remote Login: On"

  vlRunCommand systemsetup -getremotelogin
  printf "$vlCommandStdout" | grep -i "Error" >/dev/null 2>&1
  if (( $? == 0 )); then
      vlReportErrorJson \
        "$testName" \
        "$displayName" \
        "$description" \
        1 \
        "$vlCommandStdout"
      return 2
  fi

  local resultDataPropertyName="RemoteLoginEnabled"
  printf "$vlCommandStdout" | grep -i "$expectedOutput" >/dev/null 2>&1
  case $? in
    0)
      # Remote Login is enabled
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "true")
      ;;
    1)
      # Remote Login is disabled
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${resultDataPropertyName}" "false")

      # TODO: review this!
      local testScore=10
      local riskScore=40

      vlCreateResultObject \
        "$testName" \
        "$displayName" \
        "$description" \
        "$testScore" \
        "$riskScore" \
        "$resultDataForAllTests"

      return 1
      ;;
    *)
      vlReportErrorJson \
        "$testName" \
        "$displayName" \
        "$description" \
        "$grepStatus" \
        "Internal test error: pattern matching failed."
      return 2
      ;;
  esac

  return 0
}


# Score:
#   10  Root login is disabled.
#    7  Allow only specific commands to be executed by the root user.
#    4  Allow root login but only with key-based methods.
#    0  Allow root login with any authentification method.
#
#   On error, the appropriate JSON is output to stdout and a non-zero value is returned.
vlCheckRootLoginDisabled()
{
  local testName="SSHRootLoginDisabled"
  local testDisplayName="macOS root login"
  local testDescription="This test validates whether root login via SSH is permitted. It is crucial to securing a system, as the root user has full privileges and can potentially cause system-wide changes."

  local rootLogin="${sshdConfiguration[PermitRootLogin]}"
  case "$rootLogin" in
    no)
      scoresForAllTests+=(10)
      ;;
    forced-commands-only)
      scoresForAllTests+=(7)
      ;;
    prohibit-password|without-password)
      scoresForAllTests+=(4)
      ;;
    yes)
      scoresForAllTests+=(0)
      ;;
    *)
      vlReportErrorJson \
        "$testName" \
        "$displayName" \
        "$description" \
        1 \
        "Invalid value for PermitRootLogin: $rootLogin"

      return 1
      ;;
  esac

  resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "AllowRootLogin" "${rootLogin}")

  return 0
}


vlCheckSshPasswordLoginDisabled()
{
  local testName="SSHPasswordLoginDisabled"
  local testDisplayName="macOS remote password login"
  local testDescription="Disabling password login over SSH reduces the risk of brute force attacks by requiring more secure cryptographic keys for access. Checks whether remote password logins are disabled on macOS."
  local riskScore=50

  local score=10
  local isDisabled=true
  if [ "${sshdConfiguration[PasswordAuthentication]}" = "yes" ]; then
    score=$( vlGetMinScore "$riskScore" )
    isDisabled=false
  fi

  scoresForAllTests+=(${score})
  resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "PasswordAuthDisabled" $isDisabled)

  return 0
}


vlCheckSshFipsCompliant()
{
  local testName="SSHFipsCompliantConfig"
  local testDisplayName="macOS remote login FIPS compliance"
  local testDescription="Making remote logins FIPS (Federal Information Processing Standards) compliant, enhances security by enforcing stringent encryption standards. Checks whether the remote login configuration is FIPS compliant."
  local riskScore=60

  # see appleSshAndFips(7)
  local rc=1
  local isFipsCompliant=false
  if [ "${sshdConfiguration[Ciphers]}" = "aes128-gcm@openssh.com" \
    -a "${sshdConfiguration[HostbasedAcceptedAlgorithms]}" = "$(vlGetComparableOptionString ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com)" \
    -a "${sshdConfiguration[HostKeyAlgorithms]}" = "$(vlGetComparableOptionString ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com)" \
    -a "${sshdConfiguration[KexAlgorithms]}" = "ecdh-sha2-nistp256" \
    -a "${sshdConfiguration[MACs]}" = "hmac-sha2-256" \
    -a "${sshdConfiguration[PubkeyAcceptedAlgorithms]}" = "$(vlGetComparableOptionString ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com)" \
    -a "${sshdConfiguration[CASignatureAlgorithms]}" = "ecdsa-sha2-nistp256" ]
  then
    isFipsCompliant=true
    scoresForAllTests+=(10)
    rc=0
  fi

  resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "FipsCompliant" $isFipsCompliant)

  return $rc
}


vlFilterNonCompliantAlgos()
{
  local expectedArray=("${(@s:,:)1}")
  local actualArray=("${(@s:,:)2}")

  typeset -A expectedMap
  for value in "${expectedArray[@]}"; do
    expectedMap[$value]=1
  done

  local badValues=()
  for value in "${actualArray[@]}"; do
    if [[ -z ${expectedMap[$value]} ]]; then
      badValues+=($value)
    fi
  done

  printf "${(j:,:)badValues}\n"
  return ${#badValues[@]}
}


vlFilterRiskyAlgos()
{
  local riskyAlgosArray=("${(@s:,:)1}")
  local actualAlgosArray=("${(@s:,:)2}")

  typeset -A riskyAlgosMap
  for value in "${riskyAlgosArray[@]}"; do
    riskyAlgosMap[$value]=1
  done

  local riskyAlgos=()
  for value in "${actualAlgosArray[@]}"; do
    if [[ -n ${riskyAlgosMap[$value]} ]]; then
      riskyAlgos+=($value)
    fi
  done

  printf "${(j:,:)riskyAlgos}\n"
  return ${#riskyAlgos[@]}
}


vlScoreAlgorithmList()
{
  local prefix="$1"
  local goodAlgosList="$2"
  local knownRiskyAlgos="$3"
  local algosListToCheck="$4"

  local score=10
  local nonCompliantAlgosList
  nonCompliantAlgosList=$( vlFilterNonCompliantAlgos "$goodAlgosList" "${algosListToCheck}" )
  if (( $? != 0 )); then
    resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${prefix}-NonCompliantAlgorithms" "$nonCompliantAlgosList")

    local riskyAlgosList
    riskyAlgosList=$( vlFilterRiskyAlgos "$knownRiskyAlgos" "$nonCompliantAlgosList" )
    if (( $? == 0 )); then
      score=5
    else
      resultDataForAllTests=$(vlAddResultValue "${resultDataForAllTests}" "${prefix}-CriticalRiskAlgorithms" "$riskyAlgosList")
      score=0
    fi
  fi

  scoresForAllTests+=(${score})
}


vlCheckKeysStrongEncryption()
{
  local testName="SSHKeysUseStrongEncryption"
  local testDisplayName="macOS remote login key encryption"
  local testDescription="Checks whether the symmetric key algorithms that are used for remote login are considered strong."
  local riskScore=100

  local knownRiskyAlgos="diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"
  ## see https://infosec.mozilla.org/guidelines/openssh
  local goodAlgosList="curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"

  vlScoreAlgorithmList \
    "SshKexAlgorithms" \
    "$goodAlgosList" \
    "$knownRiskyAlgos" \
    "${sshdConfiguration[KexAlgorithms]}"
}


vlCheckCiphersStrongEncryption()
{
  local testName="SSHCiphersUseStrongEncryption"
  local testDisplayName="macOS remote login ciphers"
  local testDescription="Checks whether the cipher algorithms that are used for remote login are considered strong."
  local riskScore=100

  local knownRiskyAlgos="3des-cbc"
  ## see https://infosec.mozilla.org/guidelines/openssh
  local goodAlgosList="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

  vlScoreAlgorithmList \
    "SshCiphers" \
    "$goodAlgosList" \
    "$knownRiskyAlgos" \
    "${sshdConfiguration[Ciphers]}"
}


vlCheckMacsStrongEncryption()
{
  local testName="SSHMacsUseStrongEncryption"
  local testDisplayName="macOS remote login MACs"
  local testDescription="Checks whether the MAC (Message Authentication Codes) algorithms that are used for remote login are considered strong."
  local riskScore=100

  local knownRiskyAlgos="hmac-md5,hmac-md5-96,hmac-sha1,hmac-sha1-96,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com"
  ## see https://infosec.mozilla.org/guidelines/openssh
  local goodAlgosList="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"

  vlScoreAlgorithmList \
    "SshMacAlgorithms" \
    "$goodAlgosList" \
    "$knownRiskyAlgos" \
    "${sshdConfiguration[MACs]}"
}


vlReportSshTestResults()
{
  local testName="$1"
  local testDisplayName="$2"
  local testDescription="$3"
  local riskScore="$4"

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


vlSshDaemonTests()
{
  local testName="SSHDaemonTests"
  local testDisplayName="SSH daemon settings"
  local testDescription="This suite of tests performs multiple checks on the SSH daemon configuration, including remote login, password login, encryption techniques, etc., to assess the currently active settings' security level."
  local riskScore=10

  vlCheckRemoteLoginEnabled || return $(( $? - 1 ))

  vlLoadSshdConfig \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    PasswordAuthentication \
    PermitRootLogin \
    Ciphers \
    HostbasedAcceptedAlgorithms \
    HostKeyAlgorithms \
    KexAlgorithms \
    MACs \
    PubkeyAcceptedAlgorithms \
    CASignatureAlgorithms \
    || return 1

  vlCheckRootLoginDisabled || return 1
  vlCheckSshPasswordLoginDisabled || return 1

  vlCheckSshFipsCompliant
  if (( $? == 0 )); then
    # sshd is configured to be compliant with fips, which is secure and needs no further checking
    scoresForAllTests+=(10)
    vlReportSshTestResults \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$riskScore"

    return 0
  fi

  vlCheckKeysStrongEncryption
  vlCheckCiphersStrongEncryption
  vlCheckMacsStrongEncryption

  vlReportSshTestResults \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$riskScore"

  return 0
}

################################################################################
## Entry point
################################################################################

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

# Require root rights to start
[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()

results+="$( vlSshDaemonTests )"

vlPrintJsonReport "${results[@]}"
