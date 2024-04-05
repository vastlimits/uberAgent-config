#
# Security and Compliance Inventory: Network configuration 
#

vlCheckWiFiSecurity()
{
  local testName="WiFiConnectionSecurityStatus"
  local testDisplayName="WiFi Connection Security Status"
  local testDescription="WiFi connections can potentially compromise a machine's security and therefore should be encrypted. This test checks which kind of encryption the WiFi connection uses."
  local testScore=1
  local riskScore=90
   
  # Define path to the airport command-line utility
  AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
   
  # Check if Wi-Fi is enabled
  WIFI_STATUS=$($AIRPORT -I | grep 'AirPort: Off')
  if [ -n "$WIFI_STATUS" ]; then
      return 0
  fi
   
  local security="unknown"
  # Get Wi-Fi security information
  SECURITY_INFO=$($AIRPORT -I | awk '/link auth/ {print $3}')
  
  # Check if the security is one of the secure types
  case "$SECURITY_INFO" in
      wpa2-psk)
          security="WPA2"
          testScore=7
          ;;
      wpa3-sae | wpa3-psk | wpa2/wpa3-psk)
          security="WPA3"
          testScore=10
          ;;
      none | open)
          security="none"
          testScore=0
          ;;
      unknown)
          security="unknown"
          testScore=0
          ;;
      *)
          ;;
  esac
   
  resultData=$(vlAddResultValue "{}" "Security type" "$security")

  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckSmbAndNetBios()
{
  local testName="SMBv1andNetBiosStatus"
  local testDisplayName="SMBv1 and NetBIOS Status"
  local testDescription="Due to the age of SMBv1 and NetBIOS these might be prone to vulnerabilities and security issues. This test checks if they are system wide enabled (which is the default) or disabled."
  local testScore=3
  local riskScore=90

  # These are enabled by default
  local SMBv1Status="enabled"
  local NetBiosStatus="enabled" 
  
  FILE="/etc/nsmb.conf"
  SEARCH_STRING_SMB="protocol_vers_map=6"
  SEARCH_STRING_NETBIOS="port445=no_netbios"

  # Check if the file exists and if SMBv1 and/or NetBIOS is disabled
  if [ -f "$FILE" ]; then
    # Check if the file contains only the first search string on a line (ignoring leading/trailing whitespace)
    if grep -Eq "^\s*$SEARCH_STRING_SMB\s*$" "$FILE"; then
        SMBv1Status="disabled"
    fi
    
    # Check if the file contains only the second search string on a line (ignoring leading/trailing whitespace)
    if grep -Eq "^\s*$SEARCH_STRING_NETBIOS\s*$" "$FILE"; then
        NetBiosStatus="disabled"
    fi
    
    # Set the test score based on the status of SMBv1 and NetBIOS
    if [[ $SMBv1Status == "enabled" ]]; then
       testScore=3
    elif [[ $SMBv1Status == "disabled" && $NetBiosStatus == "enabled" ]]; then
       testScore=5
    elif [[ $SMBv1Status == "disabled" && $NetBiosStatus == "disabled" ]]; then
       testScore=10
    fi
  fi

  resultData=$(vlAddResultValue "{}" "SMBv1" "$SMBv1Status")
  resultData=$(vlAddResultValue "$resultData" "NetBIOS" "$NetBiosStatus")  
  
  # Create the result object 
  vlCreateResultObject "$testName" "$testDisplayName" "$testDescription" "$testScore" "$riskScore" "$resultData"
}

vlCheckInternetSharing()
{
  local testName="InternetSharingStatus"
  local testDisplayName="Internet Sharing Status"
  local testDescription="Internet Sharing allows the system to share its internet connection with other devices, potentially creating a security risk by inadvertently providing network access to unauthorized users or devices. This test checks if it is enabled/disabled."
  local testScore=10
  local riskScore=70
  
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
  local testName="AirDropStatus"
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
  local testName="AirPlayReceiverStatus"
  local testDisplayName="Airplay Receiver Status"
  local testDescription="The AirPlay Receiver under macOS is a feature that allows the computer to receive and display or play content streamed from other Apple devices. It might be a security risk as it could potentially allow unauthorized users to broadcast content if not properly secured. This test checks each user's settings."
  local testScore=10
  local riskScore=70
  
  local resultData=[]
    
  # Iterate over each user home directory in /Users
  for user_home in /Users/*; do
    # Extract the username from the home directory path
    user=$(basename "$user_home")
    
    resultObj=""
    
    # Skip the "Shared" and "Library" directories
    [[ "$user" == "Shared" || "$user" == "Library" ]] && continue
    
    # Use sudo to run 'defaults' as the user to check AirplayReceiverEnabled status
    # Yes, the option is called "AirplayRecieverEnabled" and contains a typo
    airplay_status=$(sudo -u "$user" defaults -currentHost read com.apple.controlcenter.plist AirplayRecieverEnabled 2>/dev/null)
    
    # Check if the `defaults` command succeeded
    if [[ $? -eq 0 ]]; then
      # Check the returned value and print the status
      local result="disabled"
      if [[ $airplay_status -eq 1 ]]; then
        result="enabled"
        testScore=3
      fi
      resultObj=$(vlAddResultValue "{}" "User" "$user")
      resultObj=$(vlAddResultValue "$resultObj" "Status" "$result")  
      resultData=$(vlAddResultValue "$resultData" "" "[$resultObj]")
    else
      # The following message is returned for the command above for users which have never switched the receiver off and/or on again:
      # "The domain/default pair of (com.apple.controlcenter.plist, AirplayRecieverEnabled) does not exist"
      # By default, the receiver is enabled, but we still get this message and the command is marked as failed. In this case so we have to assume the receiver is enabled.
      # If the receiver has at least once been turned off, the command above will return 0, and if switched on again it will return 1.
      resultObj=$(vlAddResultValue "{}" "User" "$user")
      resultObj=$(vlAddResultValue "$resultObj" "Status" "enabled")  
      resultData=$(vlAddResultValue "$resultData" "" "[$resultObj]")
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