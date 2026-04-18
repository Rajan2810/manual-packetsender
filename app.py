import streamlit as st
import socket
import requests
from zoneinfo import ZoneInfo
from datetime import datetime
import pandas as pd
import re
import time
import hashlib
import os
import json
from typing import Tuple, Dict, Any, Optional, List, Union

# ===== Configuration =====
# TCP endpoints for various states
TCP_ENDPOINTS = {
    "Chhattisgarh": {"ip": "164.100.64.209", "port": 6004},
    "Bihar_primary": {"ip": "164.100.64.230", "port": 9031},
    "Bihar_emergency": {"ip": "164.100.64.230", "port": 9032},
    "Uttarakhand": {"ip": "103.116.27.26", "port": 9999},
    "Chandigarh": {"ip": "164.100.64.250", "port": 9031},
    "Maharashtra": {"ip": "103.91.244.23", "port": 4030},
    "Jammu": {"ip": "164.52.220.32", "port": 2049},
    "Maharashtra_mining": {"ip": "43.205.159.137", "port": 20006},
    "MP": {"ip": "164.52.211.243", "port": 8123},
    "RJ_Emergency": {"ip": "164.100.64.203", "port": 9032},
    "RJ_primary": {"ip": "164.100.64.204", "port": 9031},
    "Goa_Emergency": {"ip": "164.100.64.247", "port": 9032},
    "Goa_Primary": {"ip": "164.100.64.226", "port": 9031}
}

# HTTP endpoints for manual data sender
HTTP_ENDPOINTS = {
    "Kerala": "http://103.135.130.119:80",
    "West Bengal": "http://117.221.20.174:80?vltdata",
}

# Timeout settings
SOCKET_TIMEOUT = 10  # seconds
HTTP_TIMEOUT = 15    # seconds

# Default values
DEFAULT_IMEI = "864568069779867"
DEFAULT_LAT = "21.258842"
DEFAULT_LON = "81.559883"
DEFAULT_VNO = "VRN_TMP22"

# Constants for validation
IMEI_LENGTH = 15
MAX_CONNECTION_RETRIES = 3
RETRY_DELAY = 1  # seconds

# Secure config file path
CONFIG_FILE = "secure_config.json"

# ===== Session State Initialization =====
def initialize_session_state():
    """Initialize all session state variables."""
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    if 'errors' not in st.session_state:
        st.session_state.errors = []
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'last_sent_packet' not in st.session_state:
        st.session_state.last_sent_packet = None
    if 'response_history' not in st.session_state:
        st.session_state.response_history = []
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    if 'last_attempt_time' not in st.session_state:
        st.session_state.last_attempt_time = 0

# ===== Authentication Functions =====
def load_credentials() -> Dict[str, str]:
    """Load credentials from a secure config file or use defaults."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                if 'credentials' in config:
                    return config['credentials']
    except Exception as e:
        log_error("Config Loading", f"Failed to load config: {e}")
    
    # Default credentials - in production, this should be replaced with secure storage
    return {"admin": hashlib.sha256("Sangwan@2002".encode()).hexdigest()}

def check_credentials(username: str, password: str) -> bool:
    """Check if the provided credentials are valid."""
    credentials = load_credentials()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if username in credentials and credentials[username] == hashed_password:
        return True
    return False

def enforce_rate_limiting() -> bool:
    """Enforce rate limiting for login attempts."""
    current_time = time.time()
    # Reset attempts if more than 15 minutes have passed
    if current_time - st.session_state.last_attempt_time > 900:  # 15 minutes
        st.session_state.login_attempts = 0
    
    st.session_state.last_attempt_time = current_time
    
    # If more than 5 failed attempts, enforce waiting period
    if st.session_state.login_attempts >= 5:
        return False
    
    return True

# ===== Logging Functions =====
def log_activity(action: str, status: str, details: str) -> None:
    """Log an activity with timestamp."""
    now = datetime.now(ZoneInfo("Asia/Kolkata"))
    st.session_state.logs.append({
        "Timestamp": now.strftime('%Y-%m-%d %H:%M:%S'),
        "Action": action,
        "Status": status,
        "Details": details
    })

def log_error(action: str, error_message: str) -> None:
    """Log an error with timestamp."""
    now = datetime.now(ZoneInfo("Asia/Kolkata"))
    st.session_state.errors.append({
        "Timestamp": now.strftime('%Y-%m-%d %H:%M:%S'),
        "Action": action,
        "Error": error_message
    })

# ===== NMEA Functions =====
def compute_nmea_checksum(data: str) -> str:
    """Compute the NMEA checksum by XORing all characters in the data string."""
    chksum = 0
    for char in data:
        chksum ^= ord(char)
    return format(chksum, '02X')

# ===== Packet Builder Functions =====
def build_packet_type1(imei: str, lat: str, lon: str, vno: str) -> str:
    """
    Build a Packet 1 (Emergency) format:
    $EPB,EMR,<IMEI>,NM,<DATE><TIME>,A,<LAT>,N,<LON>,E,0060,000.00,00.000,G,VRN_TMP22,0000000000*XX
    """
    now  = datetime.now(ZoneInfo("Asia/Kolkata"))
    date_str = now.strftime('%d%m%Y')  # ddmmyyyy
    time_str = now.strftime('%H%M%S')   # hhmmss
    data = f"EPB,EMR,{imei},NM,{date_str}{time_str},A,{lat},N,{lon},E,0060,000.00,00.000,G,{vno},0000000000"
    checksum = compute_nmea_checksum(data)
    return f"${data}*{checksum}"

def build_packet_type2(imei: str, lat: str, lon: str, vno: str) -> str:
    """
    Build a Packet 2 (Normal) format:
    $PVT,LIT1,AIS01.0,EA,11,L,<IMEI>,<VNO>,1,<DATE>,<TIME>,<LAT>,N,<LON>,E,000.00,50,23,44,
    0.42,0.79,airtel,1,1,26.5,3.8,0,C,26,405,55,0233,34AE55,39295,323,31,39295,55,27,
    3676,451,25,0,0,0,0001,01,000035,14*XX
    """
    now = datetime.now(ZoneInfo("Asia/Kolkata"))
    date_str = now.strftime('%d%m%Y')
    time_str = now.strftime('%H%M%S')
    data = (f"PVT,LIT1,AIS01.0,EA,11,L,{imei},{vno},1,{date_str},{time_str},{lat},N,{lon},E,"
            "000.00,50,23,44,0.42,0.79,airtel,1,1,26.5,3.8,0,C,26,405,55,0233,34AE55,39295,323,"
            "31,39295,55,27,3676,451,25,0,0,0,0001,01,000035,14")
    checksum = compute_nmea_checksum(data)
    return f"${data}*{checksum}"

def build_packet_type3(imei: str, lat: str, lon: str, vno: str) -> str:
    """
    Build a Packet 3 (Semi-Emergency) format:
    $EPB,SEM,<IMEI>,NM,<DATE><TIME>,A,<LAT>,N,<LON>,E,0060,000.00,00.000,G,<VNO>,0000000000*XX
    """
    now =  datetime.now(ZoneInfo("Asia/Kolkata"))
    date_str = now.strftime('%d%m%Y')
    time_str = now.strftime('%H%M%S')
    data = f"EPB,SEM,{imei},NM,{date_str}{time_str},A,{lat},N,{lon},E,0060,000.00,00.000,G,{vno},0000000000"
    checksum = compute_nmea_checksum(data)
    return f"${data}*{checksum}"

def build_http_packet(imei: str, latitude: str, longitude: str) -> str:
    """Build an HTTP packet using current date/time."""
    now = datetime.now(ZoneInfo("Asia/Kolkata"))
    date_str = now.strftime('%d%m%Y')
    time_str = now.strftime('%H%M%S')
    return (f"NRM{imei}01L1{date_str}{time_str}0{latitude}N0{longitude}E404x950D2900"
            "DC06A72000.00000.0053001811M0827.00airtel")

# ===== Communication Functions =====
def send_tcp_packet(ip: str, port: int, packet: str, retries: int = MAX_CONNECTION_RETRIES) -> str:
    """Send a TCP packet with retry logic and timeout protection."""
    attempt = 0
    while attempt < retries:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                tcp_socket.settimeout(SOCKET_TIMEOUT)
                tcp_socket.connect((ip, port))
                tcp_socket.sendall(packet.encode('utf-8'))
                
                # Try to receive response (optional)
                try:
                    response = tcp_socket.recv(1024).decode('utf-8')
                    return f"✅ TCP packet sent successfully! Response: {response}"
                except socket.timeout:
                    return f"✅ TCP packet sent successfully! (No response received)"
                
        except socket.timeout:
            attempt += 1
            if attempt < retries:
                time.sleep(RETRY_DELAY)
                continue
            return f"❌ Connection timed out after {SOCKET_TIMEOUT} seconds"
        except ConnectionRefusedError:
            return f"❌ Connection refused: The server at {ip}:{port} actively refused the connection"
        except Exception as e:
            return f"❌ Error sending TCP packet: {str(e)}"
        
        break  # Exit if successful
    
    return f"❌ Failed after {retries} attempts"

def send_http_data(api_url: str, data: Dict[str, str]) -> Tuple[str, Optional[Union[Dict[str, Any], str]]]:
    """Send data via HTTP POST request with timeout protection."""
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    try:
        response = requests.post(api_url, data=data, headers=headers, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        try:
            response_json = response.json()
            return f"✅ HTTP data sent successfully!", response_json
        except ValueError:
            return f"✅ HTTP data sent successfully!", response.text
    except requests.exceptions.Timeout:
        return f"❌ HTTP request timed out after {HTTP_TIMEOUT} seconds", None
    except requests.exceptions.ConnectionError:
        return f"❌ Connection error: Could not connect to {api_url}", None
    except requests.exceptions.RequestException as e:
        return f"❌ HTTP request failed: {str(e)}", None

# ===== Data Processing Functions =====
def extract_data_from_format(data_format: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract IMEI, latitude, and longitude from a provided format string."""
    try:
        imei = re.search(r'#(\d{15})#', data_format)
        lat_match = re.search(r'#(\d+\.\d+),N,', data_format)
        lon_match = re.search(r',N,(\d+\.\d+),E,', data_format)
        
        if not imei or not lat_match or not lon_match:
            return None, None, None
            
        imei = imei.group(1)
        lat = f"{float(lat_match.group(1)):09.6f}"
        lon = f"{float(lon_match.group(1)):09.6f}"
        return imei, lat, lon
    except (AttributeError, ValueError) as e:
        log_error("Extract Data", f"Invalid format: {str(e)}")
        return None, None, None

def validate_imei(imei: str) -> bool:
    """Validate an IMEI number."""
    return len(imei) == IMEI_LENGTH and imei.isdigit()

def validate_coordinates(lat: str, lon: str) -> bool:
    """Validate latitude and longitude coordinates."""
    try:
        lat_val = float(lat)
        lon_val = float(lon)
        return -90 <= lat_val <= 90 and -180 <= lon_val <= 180
    except ValueError:
        return False

# ===== UI Components =====
def render_login_form():
    """Render the login form with rate limiting."""
    st.subheader("Please Login")
    
    if not enforce_rate_limiting():
        st.error("Too many failed login attempts. Please try again later.")
        remaining_time = int(900 - (time.time() - st.session_state.last_attempt_time))
        st.write(f"Please wait {remaining_time // 60}m {remaining_time % 60}s before trying again.")
        return
    
    username = st.text_input('Username', key="login_username")
    password = st.text_input('Password', type='password', key="login_password")
    
    if st.button('Login', key="login_button"):
        if check_credentials(username, password):
            st.session_state.logged_in = True
            st.session_state.login_attempts = 0
            st.success('Login successful!')
            log_activity("Login", "Success", f"User {username} logged in.")
        else:
            st.session_state.login_attempts += 1
            st.error(f'Invalid credentials. Attempts: {st.session_state.login_attempts}/5')
            log_activity("Login", "Failed", f"Invalid login attempt for {username}.")

def render_tcp_sender_tab():
    """Render the TCP packet sender tab."""
    st.header("TCP Packet Sender")
    
    col1, col2 = st.columns(2)
    with col1:
        state_tcp = st.selectbox("Select State (TCP)", list(TCP_ENDPOINTS.keys()), key="tcp_state")
    with col2:
        packet_type = st.selectbox(
            "Select Packet Type", 
            ["Packet 1 (Emergency)", "Packet 2 (Normal)", "Packet 3 (Semi-Emergency)"], 
            key="tcp_packet_type",
            help="Select the type of packet to send to the server"
        )
    
    # Create two columns for layout
    col1, col2 = st.columns(2)
    
    with col1:
        imei = st.text_input(
            "IMEI (15 digits)", 
            value=DEFAULT_IMEI, 
            max_chars=IMEI_LENGTH, 
            key="tcp_imei",
            help="Enter the 15-digit IMEI number"
        )
        lat = st.text_input(
            "Latitude", 
            value=DEFAULT_LAT, 
            key="tcp_lat",
            help="Enter latitude in decimal degrees (e.g., 21.258842)"
        )
    
    with col2:
        lon = st.text_input(
            "Longitude", 
            value=DEFAULT_LON, 
            key="tcp_lon",
            help="Enter longitude in decimal degrees (e.g., 81.559883)"
        )
        vehicle_number = st.text_input(
            "Vehicle Number", 
            value=DEFAULT_VNO, 
            key="tcp_vno",
            help="Enter the vehicle registration number"
        )
    
    endpoint = TCP_ENDPOINTS[state_tcp]
    st.info(f"Target server: {endpoint['ip']}:{endpoint['port']}")
    
    if st.button("Send TCP Packet", key="tcp_send"):
        if not validate_imei(imei):
            st.error("IMEI must be a 15-digit number.")
            log_error("TCP Packet Sender", f"Invalid IMEI: {imei}")
            return
            
        if not validate_coordinates(lat, lon):
            st.error("Invalid latitude or longitude values.")
            log_error("TCP Packet Sender", f"Invalid coordinates: Lat={lat}, Lon={lon}")
            return
            
        # Build the selected packet
        packet_label = packet_type.split(' ')[0] + " " + packet_type.split(' ')[1]
        if "Packet 1" in packet_type:
            packet = build_packet_type1(imei, lat, lon, vehicle_number)
        elif "Packet 2" in packet_type:
            packet = build_packet_type2(imei, lat, lon, vehicle_number)
        elif "Packet 3" in packet_type:
            packet = build_packet_type3(imei, lat, lon, vehicle_number)
        
        # Store the packet for display
        st.session_state.last_sent_packet = packet
        
        with st.spinner(f"Sending {packet_label} to {state_tcp}..."):
            result = send_tcp_packet(endpoint["ip"], endpoint["port"], packet)
            
        if "✅" in result:
            st.success(result)
            log_activity("TCP Packet Sender", "Success", f"State: {state_tcp}, Type: {packet_type}")
            st.session_state.response_history.append({
                "timestamp": datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S'),
                "packet_type": packet_label,
                "state": state_tcp,
                "result": "Success",
                "message": result
            })
        else:
            st.error(result)
            log_error("TCP Packet Sender", result)
            st.session_state.response_history.append({
                "timestamp": datetime.now(datetime.now(ZoneInfo("Asia/Kolkata"))).strftime('%Y-%m-%d %H:%M:%S'),
                "packet_type": packet_label,
                "state": state_tcp,
                "result": "Failed",
                "message": result
            })
    
    # Display the last sent packet if available
    if st.session_state.last_sent_packet:
        with st.expander("Last Packet Sent"):
            st.code(st.session_state.last_sent_packet)

def render_http_sender_tab():
    """Render the HTTP data sender tab."""
    st.header("HTTP Manual Data Sender")
    
    col1, col2 = st.columns(2)
    
    with col1:
        state_http = st.selectbox(
            "Select State (HTTP)", 
            list(HTTP_ENDPOINTS.keys()), 
            key="http_state"
        )
    
    with col2:
        input_method = st.selectbox(
            "Input Method", 
            ["Manual Entry", "Extract from Format"], 
            key="http_input_method",
            help="Choose how to input the device data"
        )
    
    api_url = HTTP_ENDPOINTS[state_http]
    
    
    if input_method == "Manual Entry":
        col1, col2 = st.columns(2)
        
        with col1:
            imei_list = st.text_area(
                "IMEIs (comma-separated, each 15 digits)", 
                key="http_imei_list",
                help="Enter one or more IMEIs separated by commas"
            )
            
        with col2:
            latitude = st.text_input(
                "Latitude", 
                value=DEFAULT_LAT, 
                key="http_lat",
                help="Enter latitude in decimal degrees"
            )
            longitude = st.text_input(
                "Longitude", 
                value=DEFAULT_LON, 
                key="http_lon",
                help="Enter longitude in decimal degrees"
            )
    else:
        data_format = st.text_area(
            "Data Format", 
            value="Format example: Device #864568069779867# located at #21.258842,N,81.559883,E,",
            key="http_data_format",
            help="Include markers: '#<15-digit IMEI>#', '#<lat>,N,' and ',N,<lon>,E,'"
        )
    
    if st.button("Send HTTP Data", key="http_send"):
        imei_processed = []
        
        if input_method == "Extract from Format":
            imei_http, latitude, longitude = extract_data_from_format(data_format)
            if not imei_http or not latitude or not longitude:
                st.error("Failed to extract data from format. Check if markers are correctly placed.")
                log_error("HTTP Data Sender", "Extraction error from format")
                return
                
            if not validate_coordinates(latitude, longitude):
                st.error(f"Invalid coordinates extracted: Lat={latitude}, Lon={longitude}")
                log_error("HTTP Data Sender", f"Invalid coordinates: Lat={latitude}, Lon={longitude}")
                return
                
            imei_list = imei_http  # Extraction mode: single IMEI
        else:
            if not imei_list.strip():
                st.error("Please enter at least one IMEI number.")
                log_error("HTTP Data Sender", "No IMEI provided")
                return
                
            if not validate_coordinates(latitude, longitude):
                st.error("Invalid latitude or longitude values.")
                log_error("HTTP Data Sender", f"Invalid coordinates: Lat={latitude}, Lon={longitude}")
                return
                
            imei_list = [x.strip() for x in imei_list.split(",") if x.strip()]
        
        progress_bar = st.progress(0)
        status_placeholder = st.empty()
        
        for idx, imei in enumerate(imei_list if isinstance(imei_list, list) else [imei_list]):
            progress = (idx / len(imei_list if isinstance(imei_list, list) else [imei_list])) * 100
            progress_bar.progress(int(progress))
            status_placeholder.write(f"Processing IMEI: {imei} ({idx+1}/{len(imei_list if isinstance(imei_list, list) else [imei_list])})")
            
            if not validate_imei(imei):
                st.error(f"Invalid IMEI: {imei} - must be a 15-digit number")
                log_error("HTTP Data Sender", f"Invalid IMEI: {imei}")
                continue
            
            packet_http = build_http_packet(imei, latitude, longitude)
            data_payload = {'vltdata': packet_http}
            
            with st.spinner(f"Sending data for IMEI: {imei}"):
                result_http, response_content = send_http_data(api_url, data_payload)
            
            if "✅" in result_http:
                st.success(f"{result_http} for IMEI: {imei}")
                st.code(f"Packet Sent: {packet_http}")
                log_activity("HTTP Data Sender", "Success", f"IMEI: {imei}, Packet: {packet_http}")
                imei_processed.append(imei)
                
                response_display = st.expander(f"Response for IMEI: {imei}")
                with response_display:
                    if response_content:
                        if isinstance(response_content, dict):
                            st.json(response_content)
                        else:
                            st.text(response_content)
                    else:
                        st.info("No response content received from server")
            else:
                st.error(f"{result_http} for IMEI: {imei}")
                log_error("HTTP Data Sender", f"IMEI: {imei}, Error: {result_http}")
        
        progress_bar.progress(100)
        status_placeholder.write(f"Completed processing {len(imei_processed)} IMEIs successfully")

def render_logs_tab():
    """Render the activity and error logs tab."""
    st.header("Activity & Error Logs")
    
    tab1, tab2, tab3 = st.tabs(["Activity Logs", "Error Logs", "Response History"])
    
    with tab1:
        if st.session_state.logs:
            df_logs = pd.DataFrame(st.session_state.logs)
            
            # Add search functionality
            search_term = st.text_input("Search logs:", key="search_logs")
            if search_term:
                filtered_df = df_logs[df_logs.astype(str).apply(lambda x: x.str.contains(search_term, case=False)).any(axis=1)]
                st.dataframe(filtered_df, use_container_width=True)
            else:
                st.dataframe(df_logs, use_container_width=True)
            
            csv_logs = df_logs.to_csv(index=False).encode('utf-8')
            st.download_button("Download Activity Logs (CSV)", data=csv_logs, file_name='activity_logs.csv', mime='text/csv')
            
            # Add clear logs button
            if st.button("Clear Activity Logs"):
                st.session_state.logs = []
                st.success("Activity logs cleared successfully!")
                st.rerun()
        else:
            st.info("No activity logs yet.")
    
    with tab2:
        if st.session_state.errors:
            df_errors = pd.DataFrame(st.session_state.errors)
            
            # Add search functionality
            search_term = st.text_input("Search errors:", key="search_errors")
            if search_term:
                filtered_df = df_errors[df_errors.astype(str).apply(lambda x: x.str.contains(search_term, case=False)).any(axis=1)]
                st.dataframe(filtered_df, use_container_width=True)
            else:
                st.dataframe(df_errors, use_container_width=True)
            
            csv_errors = df_errors.to_csv(index=False).encode('utf-8')
            st.download_button("Download Error Logs (CSV)", data=csv_errors, file_name='error_logs.csv', mime='text/csv')
            
            # Add clear logs button
            if st.button("Clear Error Logs"):
                st.session_state.errors = []
                st.success("Error logs cleared successfully!")
                st.rerun()
        else:
            st.info("No error logs yet.")
    
    with tab3:
        if st.session_state.response_history:
            df_history = pd.DataFrame(st.session_state.response_history)
            st.dataframe(df_history, use_container_width=True)
            
            # Add clear history button
            if st.button("Clear Response History"):
                st.session_state.response_history = []
                st.success("Response history cleared successfully!")
                st.rerun()
        else:
            st.info("No response history yet.")


    

# ===== Main Application =====
def main():
    """Main application function."""
    st.set_page_config(
        page_title="Packet Sender Dashboard",
        page_icon="🚚",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    initialize_session_state()
    
    st.title("🚚 Complete Packet Sender Dashboard")
    
    # Only show sidebar when logged in
    if st.session_state.logged_in:
        with st.sidebar:
            st.header("Navigation")
            st.write("Use the tabs below to access different features.")
            
            # Add logout button
            if st.button("Logout"):
                st.session_state.logged_in = False
                log_activity("Logout", "Success", "User logged out")
                st.rerun()
                
            st.divider()
            st.write("Current Time (IST):")
            st.code(datetime.now(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S'))
    
    # Authentication check
    if not st.session_state.logged_in:
        render_login_form()
        return
    
    # Main tabs for functionality
    tab_tcp, tab_http, tab_logs = st.tabs([
        "TCP Packet Sender", 
        "HTTP Data Sender", 
        "Activity Logs", 
        
    ])
    
    # Display content based on selected tab
    with tab_tcp:
        render_tcp_sender_tab()
    
    with tab_http:
        render_http_sender_tab()
    
    with tab_logs:
        render_logs_tab()


if __name__ == "__main__":
    main()