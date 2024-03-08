#
# Security and Compliance Inventory: Network configuration 
#

vlCheckWiFiSecurity()
{
  local testName="WiFiConnectionSecurity"
  local testDisplayName="WiFi Connection Security Status"
  local testDescription="WiFi connections should be secured with at least WPA2. This test checks if a WiFi connection is used and if WPA2 oder higher is enabled."
  local testScore=1
  local riskScore=80

  local WiFiEnabled="false"
  local WiFiIsSecure="Secure"
  local WiFiIsNotSecure="Insecure"
  local WiFiUnknown="Unknown"
   
  # Define path to the airport command-line utility
  AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
   
  # Check if Wi-Fi is enabled
  WIFI_STATUS=$($AIRPORT -I | grep 'AirPort: Off')
  if [ -n "$WIFI_STATUS" ]; then
      WiFiEnabled="false"
  else
      WiFiEnabled="true"
  fi
   
  local security=""
  if [ $WiFiEnabled = "true" ]; then
      # Get Wi-Fi security information
      SECURITY_INFO=$($AIRPORT -I | awk '/link auth/ {print $3}')
      
      # Check if the security is one of the secure types
      case "$SECURITY_INFO" in
          wpa2-psk)
              security=$WiFiIsSecure
              testScore=7
              ;;
          wpa3-sae | wpa3-psk | wpa2/wpa3-psk)
              security=$WiFiIsSecure
              testScore=10
              ;;
          none | open)
              security=$WiFiIsNotSecure
              testScore=1
              ;;
          unknown)
              security=$WiFiIsUnknown
              testScore=1
              ;;
          *)
              ;;
      esac
       
      resultObj1=$(vlAddResultValue "{}" "Status" "on")
      resultObj2=$(vlAddResultValue "{}" "Connection" "$security")
      resultData=$(vlAddResultValue "[]" "" "[$resultObj1, $resultObj2]")
  else
      testScore=10
      resultData=$(vlAddResultValue "{}" "Status" "off")
  fi
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckSmbAndNetBios()
{
  local testName="SMBv1andNetBiosTest"
  local testDisplayName="SMBv1 and NetBIOS Status"
  local testDescription="Due to the age of SMBv1 and NetBIOS these might be prone to vulnerabilities and security issues. This test checks if they are system wide enabled (which is the default) or disabled."
  local testScore=2
  local riskScore=80

  # These are enabled by default
  local SMBv1Status="enabled"
  local NetBiosStatus="enabled" 
  
  FILE="/etc/nsmb.conf"
  SEARCH_STRING_SMB="protocol_vers_map=6"
  SEARCH_STRING_NETBIOS="port445=no_netbios"

  # Check if the file exists and if SMBv1 and/or NetBIOS is disabled
  # If the file doesn't exist, assume both SMBv1 and NetBIOS are enabled
  if [ -f "$FILE" ]; then
      # Check if the file contains only the first search string on a line (ignoring leading/trailing whitespace)
      if grep -Eq "^\s*$SEARCH_STRING_SMB\s*$" "$FILE"; then
          SMBv1Status="disabled"
          testScore=10
      fi
  
      # Check if the file contains only the second search string on a line (ignoring leading/trailing whitespace)
      if grep -Eq "^\s*$SEARCH_STRING_NETBIOS\s*$" "$FILE"; then
          NetBiosStatus="disabled"
          testScore=10
      fi
  fi  

  resultObj1=$(vlAddResultValue "{}" "SMBv1" "$SMBv1Status")
  resultObj2=$(vlAddResultValue "{}" "NetBIOS" "$NetBiosStatus")
  resultData=$(vlAddResultValue "[]" "" "[$resultObj1, $resultObj2]")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

# Initialize the vl* utility functions
vlUtils="$(cd "$(dirname "$0")/.." && pwd)/Utils.zsh"
. "$vlUtils" && vlInit

[ "$(id -u)" = "0" ] || { printf "Error: This script must be run as root.\n" >&2; exit 64; }

# Run the tests
results=()
results+="$( vlCheckWiFiSecurity )"
results+="$( vlCheckSmbAndNetBios )"
# Print the results as JSON
vlPrintJsonReport "${results[@]}"