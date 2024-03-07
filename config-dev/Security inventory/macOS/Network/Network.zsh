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
       
      resultObj1=$(vlAddResultValue "{}" "Status" "On")
      resultObj2=$(vlAddResultValue "{}" "Connection" "$security")
      resultData=$(vlAddResultValue "[]" "" "[$resultObj1, $resultObj2]")
  else
      testScore=10
      resultData=$(vlAddResultValue "{}" "Status" "Off")
  fi
  
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
# Print the results as JSON
vlPrintJsonReport "${results[@]}"