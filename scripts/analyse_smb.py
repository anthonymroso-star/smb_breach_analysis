"""
================================================================================
Compliance Note: Where applicable, files, scripts, logs, IP addresses, 
hostnames, and architecture identities have been sanitized and anonymized 
in alignment with relevant security frameworks and responsible-disclosure guidelines.
================================================================================
"""
from scapy.all import rdpcap
from datetime import datetime
import struct
import os

# Natively calculate the absolute path to the active script file location
script_dir = os.path.dirname(os.path.abspath(__file__))

# Map a direct path to the sanitized packet capture file
target_pcap_path = os.path.join(script_dir, "../artifacts/smb_breach_sanitized.pcapng")

print("Opening forensic file...")
print(f"    - Targeted File Path: {os.path.abspath(target_pcap_path)}")

# Verification check: Stop if the file path is incorrect
if not os.path.exists(target_pcap_path):
    print(f"\n[-] CRITICAL ERROR: Could not locate 'smb_breach_sanitized.pcapng'.")
    print("    - Action: Ensure sanitize_wire.py tool ran successfully.")
    print("    - Action: Verify the output sits inside the 'artifacts' folder directory.")
    exit()

# Load the sanitized capture data straight out of the artifacts folder
packets = rdpcap(target_pcap_path)

# A blank dictionary to dynamically map unknown external IPs to packet counts
network_conversations = {}

# Variables to capture the exact time window of the Port 445 conversation
first_packet_time = None
last_packet_time = None

# Counter to track confirmed application-layer SMB2 data packets
smb2_packet_count = 0

# Counters to track granular application-layer security indicators
failed_logon_count = 0
successful_foothold_count = 0

# List array to dynamically capture and store unknown file names accessed on the wire
accessed_files_vault = []

print("Scanning network headers for full two-way Port 445 conversations...")
for packet in packets:
    # Rule 1: Strip away generic hardware and isolate valid IPv4 network headers
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
        
        # Check if Port 445 is involved on either side of the network connection
        if sport == 445 or dport == 445:
            
            # If the sanitized server is the sender, the external system is the destination
            if src_ip == "192.168.10.10":
                external_ip = dst_ip
            # If the server is the receiver, the external system is the source
            else:
                external_ip = src_ip
                
            # Log the two-way packet volume for this specific external system
            network_conversations[external_ip] = network_conversations.get(external_ip, 0) + 1

            # Extract the raw epoch decimal timestamp from the packet metadata
            raw_time = packet.time
            # Convert the raw decimal into a human-readable standard format string
            readable_time = datetime.fromtimestamp(float(raw_time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
            if first_packet_time is None:
                first_packet_time = readable_time
            last_packet_time = readable_time

            # Rule 4: Verify if the TCP layer is actively carrying true application data bytes
            if packet.haslayer("TCP"):
                payload_length = len(packet["TCP"].payload)
                
                # If the payload length is greater than 0, it is actively executing file-sharing commands
                if payload_length > 0:
                    smb2_packet_count += 1
                    
                    # Force conversion to a raw binary byte array to prevent attribute crashes
                    payload_bytes = bytes(packet["TCP"].payload)
                    
                    # Locate the exact starting byte index of the SMB2 protocol signature
                    smb_start_index = payload_bytes.find(b"\xfeSMB")
                    
                    # Only slice if the signature was actually located in the stream
                    if smb_start_index != -1:
                        # Slice the data to isolate the 64-byte SMB2 protocol header
                        smb_header = payload_bytes[smb_start_index:]
                        
                        # Verify the header slice contains at least 14 bytes to allow safe reading
                        if len(smb_header) >= 14:
                            # Extract bytes and use [0] to peel them straight out of the tuple envelopes
                            nt_status = struct.unpack("<I", smb_header[8:12])[0]
                            command_id = struct.unpack("<H", smb_header[12:14])[0]
                            
                            # Filter strictly for Command ID 1: Session Setup (The Authentication Phase)
                            if command_id == 1:
                                
                                # 3221225581 is the raw decimal representation of 0xc000006d (STATUS_LOGON_FAILURE)
                                if nt_status == 3221225581:
                                    failed_logon_count += 1
                                    
                                # 0 is the universal protocol representation of STATUS_SUCCESS
                                elif nt_status == 0:
                                    successful_foothold_count += 1
                                    
                            # Filter for Command ID 5: SMB2 Create (File / Directory Open Request)
                            elif command_id == 5 and nt_status == 0:
                                # In an SMB2 Create response, the filename text sits past the 64-byte header
                                payload_string = smb_header[64:]
                                
                                # Clean the raw bytes to extract readable alphanumeric text strings
                                if b"\\" in payload_string or len(payload_string) > 0:
                                    # Decode the binary string to standard UTF-8 text, ignoring null bytes
                                    clean_name = payload_string.decode('utf-8', errors='ignore').replace('\x00', '').strip()
                                    
                                    # Filter out generic protocol chatter names and save true assets
                                    if len(clean_name) > 2 and clean_name not in accessed_files_vault:
                                        # Strip any remaining non-printable characters
                                        filtered_name = "".join(c for c in clean_name if c.isalnum() or c in "._-\\/")
                                        if len(filtered_name) > 3:
                                            accessed_files_vault.append(filtered_name)

print("\n" + "="*50)
print("             SOC FORENSIC PROTOCOL REPORT             ")
print("="*50)
if network_conversations:
    for ip, count in network_conversations.items():
        print(f"[+] UNMASKED ATTACK ENVIRONMENT IP: {ip}")
        print(f"    - Total Network Layer Volume: {count} packets (Requests & Responses).")
    
    print("\n[+] TEMPORAL BOUNDARY VERIFICATION:")
    print(f"    - Conversation Commencement : {first_packet_time}")
    print(f"    - Conversation Termination  : {last_packet_time}")
    
    print("\n[+] APPLICATION LAYER TELEMETRY:")
    print(f"    - Confirmed SMB2 Data Packets: {smb2_packet_count} packets verified.")
    print(f"    - Extracted Logon Failures   : {failed_logon_count} (STATUS_LOGON_FAILURE).")
    print(f"    - Confirmed Success Footholds: {successful_foothold_count} (STATUS_SUCCESS).")
    
    print("\n[+] IDENTIFIED DATA ASSETS ACCESSED:")
    if accessed_files_vault:
        for filename in accessed_files_vault:
            print(f"    - Target Asset Opened: {filename}")
    else:
        print("    - No explicit file or folder paths decoded inside payloads.")
else:
    print("[-] No bidirectional Port 445 traffic identified on the wire.")
print("="*50)

