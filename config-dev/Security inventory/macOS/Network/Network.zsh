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

vlCheckInternetSharing()
{
  local testName="InternetSharingTest"
  local testDisplayName="Internet Sharing Status"
  local testDescription="Internet Sharing allows the system to share its internet connection with other devices, potentially creating a security risk by inadvertently providing network access to unauthorized users or devices. This test checks if it is configured and/or enabled/disabled."
  local testScore=10
  local riskScore=80
  
  # Internet Sharing is disabled and not configured by default
  local sharingStatus="disabled"
  
  # Command to check Internet Sharing status
  output=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat 2>&1)
  
  # Check if the domain exists
  if [[ $output != *"Domain /Library/Preferences/SystemConfiguration/com.apple.nat does not exist"* ]]; then
    # Check if Internet Sharing is enabled or not
    if echo "$output" | grep -q "Enabled = 1"; then
      sharingStatus="enabled"
      testScore=2
    fi
  fi

  resultData=$(vlAddResultValue "{}" "Status" "$sharingStatus")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckAirDrop()
{
  local testName="AirDropTest"
  local testDisplayName="AirDrop Status"
  local testDescription="AirDrop is a file-sharing feature built into macOS that uses Wi-Fi and Bluetooth for peer-to-peer transfers. This can be a security risk because it may allow harmful content to be sent from unknown devices. This test checks if AirDrop is enabled."
  local testScore=10
  local riskScore=80
  
  local wifiEnabled="false"
  local blueToothEnabled="false"
  local sharingDaemonRunning="false"
  local interfaceAwdl0Active="false"
  local airdropStatus="disabled"
  
  # Check Wi-Fi Status
  wifi_status=$(/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I | awk '/state:/ {print $2}')
  if [[ $wifi_status == "running" ]]; then
      wifiEnabled="true"
  fi
  
  # Check Bluetooth Status using system_profiler and awk
  bluetooth_info=$(system_profiler SPBluetoothDataType)
  bluetooth_status=$(echo "$bluetooth_info" | awk '/State:/{print $2}')
  
  if [[ $bluetooth_status == "On" ]]; then
      blueToothEnabled="true"
  fi
  
  # Check if sharingd is running
  sharingd_pid=$(pgrep sharingd)
  if [[ $sharingd_pid ]]; then
      sharingDaemonRunning="true"
  fi
  
  # Check the status of the awdl0 interface
  awdl_status=$(ifconfig awdl0 | grep "status: " | awk '{print $2}')
  if [[ $awdl_status == "active" ]]; then
      interfaceAwdl0Active="true"
  fi
  
  # Infer AirDrop status based on above checks
  if [[ $wifiEnabled == "true" && $blueToothEnabled == "true" && $sharingDaemonRunning == "true" && $interfaceAwdl0Active == "true" ]]; then
      airdropStatus="enabled"
      testScore=5
  else
      airdropStatus="disabled"
      testScore=10
  fi
  
  resultData=$(vlAddResultValue "{}" "Status" "$airdropStatus")
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
  
}

vlCheckAirplayReceiver()
{
  local testName="AirPlayReceiverTest"
  local testDisplayName="Airplay Receiver Status"
  local testDescription="The AirPlay Receiver under macOS is a feature that allows the computer to receive and display or play content streamed from other Apple devices. It might be a security risk as it could potentially allow unauthorized users to broadcast content if not properly secured. This test checks each user's settings."
  local testScore=10
  local riskScore=80
  
  local resultData=""
  
  # Iterate over each user home directory in /Users
  for user_home in /Users/*; do
    # Extract the username from the home directory path
    user=$(basename "$user_home")

    # Skip the "Shared" directory
    [[ "$user" == "Shared" ]] && continue
    
    # Use sudo to run 'defaults' as the user to check AirplayReceiverEnabled status
    # Yes, the option is called "AirplayRecieverEnabled" and contains a typo
    airplay_status=$(sudo -u "$user" defaults -currentHost read com.apple.controlcenter.plist AirplayRecieverEnabled 2>/dev/null)
    
    # Check if the `defaults` command succeeded
    if [[ $? -eq 0 ]]; then
      # Check the returned value and print the status
      local result="disabled for $user"
      if [[ $airplay_status -eq 1 ]]; then
        result="enabled for $user"
        testScore=3
      fi
      resultData+=$(vlAddResultValue "{}" "Status" "$result")
    fi
  done
  
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
results+="$( vlCheckInternetSharing )"
results+="$( vlCheckAirDrop )"
results+="$( vlCheckAirplayReceiver )"
# Print the results as JSON
vlPrintJsonReport "${results[@]}"