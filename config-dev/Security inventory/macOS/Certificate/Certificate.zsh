#
# Security and Compliance Inventory: Certificates
#

vlReportTrustStoreVersion()
{
  local testName="CertTSVerRep"
  local testDisplayName="Trust Store Version"
  local testDescription="This test retrieves and reports the version of the macOS Trust Store, which is an unmodifiable repository of system root certificates. The Trust Store not only validates trusted certificates but also manages blocked ones, serving as an implicit Certificate Revocation List (CRL). Keeping track of the Trust Store version helps ensure system security by verifying that the system is up-to-date with the latest trust settings."
  # Informative test: always scores 10 and the riskScore is zero
  local riskScore=0
  local testScore=10

  vlRunCommand defaults read /System/Library/Security/Certificates.bundle/Contents/version.plist CFBundleVersion

  if (( $vlCommandStatus != 0 )); then
    vlReportErrorJson \
      "$testName" \
      "$testDisplayName" \
      "$testDescription" \
      "$vlCommandStatus" \
      "$vlCommandStderr"
    return 1
  fi

  local resultData=$(vlAddResultValue "{}" "Version" "$(echo "$vlCommandStdout" | tr -d '\n')")

  vlCreateResultObject \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$resultData"
}

vlCheckSystemKeychainCerts()
{
  local testName="CMTrByMac"
  local testDisplayName="Certificates trusted by macOS - Machine"
  local testDescription="This test examines the system keychain for any trusted root CA certificates added by an admin. These certificates, if present, could alter the default trust settings of the system and potentially introduce security risks. The absence of admin-added certificates is considered a good state, while their presence requires further investigation to ensure system integrity."
  local riskScore=70

  keychainCheckCertCount=0
  keychainCheckResult="[]"
  certTrustMap=()

  vlBuildCertTrustMap "$( security dump-trust-settings -d 2>/dev/null )"
  # Ignore the self-signed machine certificates installed by macOS
  vlCheckKeychains \
    "" \
    "$( security list-keychains -d system)" \
    com.apple.kerberos.kdc com.apple.systemdefault

  local testScore=10
  if (( keychainCheckCertCount > 0 )); then
    testScore=5
  fi

  vlCreateResultObjectWithScope \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$keychainCheckResult" \
    1
}

vlCheckUserKeychains()
{
  local testName="CUTrByMac"
  local testDisplayName="Certificates trusted by macOS - User"
  local testDescription="This test checks all user keychains for any added trusted root CA certificates. Similar to the system keychain, user-added certificates in their keychains could affect the system's trust settings on a per-user basis. The absence of user-added certificates is considered a good state, while their presence could indicate potential security concerns that need to be addressed."
  local riskScore=70

  keychainCheckCertCount=0
  keychainCheckResult="[]"

  # In UNIX-based systems like macOS, user accounts with a UID less than 500 are typically system accounts.
  for username in $(dscl . -list /Users UniqueID | awk '$2 > 500 { print $1 }'); do
    # Users with a new password required policy will block the su(1) command execution, so skip
    local pwdPolicy="$( pwpolicy -u $username -getpolicy | grep newPasswordRequired )"
    if [[ -z "$pwdPolicy" ]] \
      || [[ "$pwdPolicy" = "newPasswordRequired=0" ]]
    then
      vlBuildCertTrustMap "$(su -l $username -c 'security dump-trust-settings 2>/dev/null')"
      vlCheckKeychains \
        "$username" \
        "$( su -l $username -c 'security list-keychains -d user' )"
    fi
  done

  local testScore=10
  if (( keychainCheckCertCount > 0 )); then
    testScore=5
  fi

  vlCreateResultObjectWithScope \
    "$testName" \
    "$testDisplayName" \
    "$testDescription" \
    "$testScore" \
    "$riskScore" \
    "$keychainCheckResult" \
    2
}

typeset -A certTrustMap

# The trust map is valid for all user keychains, as the trust settings are not
# split between by keychain.
vlBuildCertTrustMap()
{
  local trustSettingsDump="$1"

  local certName=""
  local trustStatus="untrusted"

  certTrustMap=()
  while IFS= read -r line; do
    if [[ "$line" == Cert* ]]; then
      if [[ -n "$certName" ]]; then
        certTrustMap["$certName"]="$trustStatus"
      fi
      certName=$(echo "$line" | cut -d':' -f2- | xargs)
      trustStatus="untrusted"
    elif [[ "$line" == *"Result Type"* ]]; then
      if [[ "$line" == *"kSecTrustSettingsResultTrustRoot"* ]]; then
        # Only one Trust Setting is needed to consider the certificate trusted
        trustStatus="trusted"
      fi
      # We disregard kSecTrustSettingsResultTrustAsRoot because it means that the
      # certificate itself is trusted but not the certificates that it may have signed.
    fi
  done <<< "$trustSettingsDump"

  if [[ -n "$certName" ]]; then
    certTrustMap["$certName"]="$trustStatus"
  fi
}

# Determine whether a certificate is considered a trusted certificate for a single user,
# based on the certTrustMap that was established for that user.
# Note that a certificate in a user's keychain marked as trusted for *all* users is not
# covered by this test.
vlIsCertUserTrustedRoot()
{
  local certCommonName="$1"
  local singleCertData="$2"

  # The 'security dump-trust-settings' command displays a "certificate summary" as the certificate idenfier.
  # This is build using the CN. In case the CN is not available, other attributes are used.
  # See https://github.com/apple-oss-distributions/Security/blob/0600e7bab30fbac3adcafcb6c57d3981dc682304/OSX/sec/Security/SecCertificate.c#L4034
  #
  # However, since it is not possible to create a CA certificate without a CN, we can assume that the
  # CN alone will match in this case.
  local trustStatus=${certTrustMap["$certCommonName"]}
  if [[ -z "$trustStatus" ]]; then
    return 2
  fi

  if [[ "$trustStatus" = "trusted" ]]; then
    return 0
  fi

  return 1
}

# Checks whether a certificate is marked to be trusted for all users, regardless of
# which keychain the certificate is in (can be a user's keychain).
# This test complements vlIsCertUserTrustedRoot() to check for all possible trust
# settings from the command line.
vlIsCertTrustRootForAllUsers()
{
  local singleCertData="$1"

  # Ensures that the temporary file is only readable by us...
  local CERT_TMP_DIR=/tmp
  local certFile=$( mktemp "$CERT_TMP_DIR/verifyRootCert.XXXXXX" )
  # ...and that it will be deleted no matter how the script exits.
  trap 'rm -f "'"$certFile"'"' EXIT

  echo "$singleCertData" >$certFile
  security verify-cert -c $certFile >/dev/null 2>&1
  local verifyCertStatus=$?
  rm -f "$certFile"

  return $(( verifyCertStatus ))
}

vlIsRootCertificate()
{
  local singleCertData="$1"

  # Check if the certificate has the CA basic constraint set or not.
  if [[ -z "$( echo "$singleCertData" | openssl x509 -noout -text 2>/dev/null | grep 'CA:TRUE' )" ]]; then
    return 1
  fi

  # Check if the certificate is self-signed, i.e. the root CA certificate.
  local issuer="$( echo "$singleCertData" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' )"
  local subject="$( echo "$singleCertData" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' )"
  if [ "$issuer" != "$subject" ]; then
    return 1
  fi

  return 0
}

vlShouldIgnoreCertificate()
{
  local cn="$1"
  shift 1

  for ignoredCN in "$@"; do
    if [[ "$cn" = "$ignoredCN" ]]; then
      return 0
    fi
  done

  return 1
}

# Check that the specified keychain doesn't have any trusted root CA certificates
# which are presumed to have been added by the user. Ignore the certificates present
# in the ignored CN function parameter(s).
# Appends to globals (output): keychainCheckResult, keychainCheckCertCount
vlCheckKeychains()
{
  local username="$1"
  local keychains="$2"

  shift 2

  echo "$keychains" | while IFS= read -r keychainRaw
  do
    local keychainPath=$( echo "$keychainRaw" | xargs )

    IFS='|'
    for singleCertData in $( security find-certificate -a -p "$keychainPath" | \
      awk -v RS='-----END CERTIFICATE-----' \
      'NF{printf "%s|", $0 "-----END CERTIFICATE-----"}' )
    do
      [[ -n "$singleCertData" ]] || continue

      # The different fields in the subject are separated by commas. If the CN itself
      # contains commas, then they are escaped with the backslash character.
      local commonName=$(
          echo "$singleCertData" | \
          openssl x509 -noout -subject -nameopt RFC2253 2>/dev/null | \
          perl -ne 'if(/CN=((?:[^,\\]|\\.)*)/){print "$1\n"; exit}' | \
          sed 's/\\,/,/g; s/\\\\,/,/g'
      )

      vlShouldIgnoreCertificate "$commonName" $@ && continue

      vlIsRootCertificate "$singleCertData" || continue

      vlIsCertUserTrustedRoot "$commonName" "$singleCertData" \
        || vlIsCertTrustRootForAllUsers "$singleCertData" \
        || continue

      local issuer=$(echo "$singleCertData" |
                    openssl x509 -noout -issuer 2>/dev/null |
                    sed 's/issuer=//')

      local notBefore=$(echo "$singleCertData" |
                        openssl x509 -noout -startdate 2>/dev/null |
                        cut -d= -f2 |
                        xargs -I{} date -j -f "%b %d %T %Y %Z" "{}" "+%Y-%m-%dT%H:%M:%S")

      local notAfter=$(echo "$singleCertData" |
                      openssl x509 -noout -enddate 2>/dev/null |
                      cut -d= -f2 |
                      xargs -I{} date -j -f "%b %d %T %Y %Z" "{}" "+%Y-%m-%dT%H:%M:%S")

      local subject=$(echo "$singleCertData" |
                      openssl x509 -noout -subject 2>/dev/null |
                      sed 's/subject=//')

      local thumbprint=$(echo "$singleCertData" |
                        openssl x509 -noout -sha1 -fingerprint 2>/dev/null |
                        tr -d ':' |
                        cut -d= -f2)

      local certObj="{}"
      certObj=$( vlAddResultValue "${certObj}" "Issuer" "$issuer" )
      certObj=$( vlAddResultValue "${certObj}" "NotAfter" "$notAfter" )
      certObj=$( vlAddResultValue "${certObj}" "NotBefore" "$notBefore" )
      certObj=$( vlAddResultValue "${certObj}" "Subject" "$subject" )
      certObj=$( vlAddResultValue "${certObj}" "Thumbprint" "$thumbprint" )

      if [[ -n "$username" ]]; then
        certObj=$( vlAddResultValue "${certObj}" "Username" "$username" )
        local keychainName=$( basename "$keychainPath" | cut -d"." -f1 | tr '[:upper:]' '[:lower:]' )
        certObj=$( vlAddResultValue "${certObj}" "Keychain" "$keychainName" )
      fi

      keychainCheckResult=$(vlAddResultValue "$keychainCheckResult" "" "[$certObj]")
      keychainCheckCertCount=$(( keychainCheckCertCount + 1 ))
    done
  done

  if [[ -n "$username" ]] && (( keychainCheckCertCount == 0 )); then
    keychainCheckResult=$(vlAddResultValue "{}" "Username" "$username" )
  fi
}

vlCertsTests()
{
  vlReportTrustStoreVersion || return

  vlCheckUserKeychains
  vlCheckSystemKeychainCerts
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
vlPrintJsonReport "$( vlCertsTests )"
