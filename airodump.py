#!/usr/bin/env python3
"""
Wireless Network Monitoring Tool

A Python-based tool for monitoring wireless networks and clients,
similar to airodump-ng.
"""

import argparse
import os
import signal
import sys
import time
import datetime
import logging
import threading
import curses
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional, Any

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Auth, Dot11AssoReq, \
                         Dot11ProbeReq, sniff, conf, Dot11Deauth, RadioTap, rdpcap, wrpcap, \
                         PcapWriter
    from scapy.layers.dot11 import Dot11EltRates, Dot11Elt
except ImportError:
    print("Error: Scapy library not found. Please install with 'pip install scapy'")
    sys.exit(1)

# Global variables
networks = {}  # BSSID -> network info
clients = {}   # MAC -> client info
client_to_ap = {}  # Client MAC -> BSSID of associated AP
essid_to_bssid = {}  # ESSID -> BSSID
handshake_captured = set()  # Set of BSSIDs for which WPA handshake has been captured
start_time = time.time()
stop_sniffing = False
current_channel = 1
capture_ivs = False
display_wps = False
target_bssid = None
target_channel = None
output_format = None
output_file = None
output_writers = {}
window = None
screen_width = 80
interface = None

# Constants for scanning
CHANNEL_SWITCH_INTERVAL = 2  # seconds
MAX_CHANNEL = 14  # for 2.4GHz

def set_monitor_mode(interface: str) -> bool:
    """
    Set the wireless interface to monitor mode.
    
    Args:
        interface: Wireless interface name
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        os.system(f"sudo ip link set {interface} down")
        time.sleep(0.5)
        os.system(f"sudo iw {interface} set monitor control")
        time.sleep(0.5)
        os.system(f"sudo ip link set {interface} up")
        time.sleep(0.5)
        return True
    except Exception as e:
        logging.error(f"Failed to set monitor mode: {e}")
        return False

def channel_hopper(interface: str) -> None:
    """
    Hop between channels periodically.
    
    Args:
        interface: Wireless interface name
    """
    global current_channel, stop_sniffing, target_channel
    
    # If a specific channel is selected, we don't need to hop
    if target_channel:
        try:
            os.system(f"sudo iw dev {interface} set channel {target_channel}")
            current_channel = target_channel
        except Exception as e:
            logging.error(f"Failed to set channel: {e}")
        return
    
    while not stop_sniffing:
        for channel in range(1, MAX_CHANNEL + 1):
            if stop_sniffing:
                break
            
            try:
                os.system(f"sudo iw dev {interface} set channel {channel}")
                current_channel = channel
                time.sleep(CHANNEL_SWITCH_INTERVAL)
            except Exception as e:
                logging.error(f"Failed to set channel: {e}")

def parse_encryption(packet) -> Tuple[str, str, str]:
    """
    Parse encryption details from a beacon packet.
    
    Args:
        packet: Scapy packet
    
    Returns:
        Tuple[str, str, str]: (encryption, cipher, authentication)
    """
    # Default values
    encryption = "OPN"
    cipher = ""
    auth = ""
    
    # Find all Dot11Elt elements
    for element in packet.iterfind(Dot11Elt):
        # RSN (WPA2) Information Element
        if element.ID == 48:
            encryption = "WPA2"
            auth_key_count = int(element.info[6:8], 16)
            if auth_key_count == 1:
                if element.info[8:10] == b'\x00\x0f\xac\x04':
                    cipher = "CCMP"
                elif element.info[8:10] == b'\x00\x0f\xac\x02':
                    cipher = "TKIP"
            
            auth_count = int(element.info[8+4*auth_key_count:8+4*auth_key_count+2], 16)
            if auth_count == 1:
                if element.info[10+4*auth_key_count:10+4*auth_key_count+4] == b'\x00\x0f\xac\x02':
                    auth = "PSK"
                elif element.info[10+4*auth_key_count:10+4*auth_key_count+4] == b'\x00\x0f\xac\x01':
                    auth = "MGT"
                elif element.info[10+4*auth_key_count:10+4*auth_key_count+4] == b'\x00\x0f\xac\x08':
                    auth = "SAE"  # WPA3
        
        # WPA Information Element
        elif element.ID == 221 and element.info.startswith(b'\x00\x50\xf2\x01'):
            if encryption != "WPA2":  # Don't overwrite WPA2
                encryption = "WPA"
                auth_key_count = int(element.info[12:14], 16)
                if auth_key_count == 1:
                    if element.info[14:18] == b'\x00\x50\xf2\x04':
                        cipher = "CCMP"
                    elif element.info[14:18] == b'\x00\x50\xf2\x02':
                        cipher = "TKIP"
                
                auth_count = int(element.info[14+4*auth_key_count:14+4*auth_key_count+2], 16)
                if auth_count == 1:
                    if element.info[16+4*auth_key_count:20+4*auth_key_count] == b'\x00\x50\xf2\x02':
                        auth = "PSK"
                    elif element.info[16+4*auth_key_count:20+4*auth_key_count] == b'\x00\x50\xf2\x01':
                        auth = "MGT"
        
        # Privacy bit (WEP)
        elif element.ID == 221 and packet[Dot11Beacon].cap.privacy:
            if encryption == "OPN":  # Don't overwrite WPA/WPA2
                encryption = "WEP"
                cipher = "WEP"
                auth = "SKA"  # Shared Key Authentication
    
    # Check privacy bit for WEP
    if packet[Dot11Beacon].cap.privacy and encryption == "OPN":
        encryption = "WEP"
        cipher = "WEP"
        auth = "SKA"
    
    return encryption, cipher, auth

def get_max_rate(packet) -> float:
    """
    Get the maximum rate supported by the AP.
    
    Args:
        packet: Scapy packet
    
    Returns:
        float: Maximum rate in Mbps
    """
    max_rate = 0
    
    # Check extended rates
    rates_elt = packet.iterfind(Dot11EltRates)
    for rates in rates_elt:
        for rate in rates.info:
            r = (rate & 0x7F) * 0.5
            if r > max_rate:
                max_rate = r
    
    return max_rate

def get_essid(packet) -> str:
    """
    Extract ESSID from packet.
    
    Args:
        packet: Scapy packet
    
    Returns:
        str: ESSID (network name)
    """
    essid = ""
    
    if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
        try:
            essid = packet[Dot11Elt].info.decode('utf-8')
        except UnicodeDecodeError:
            essid = packet[Dot11Elt].info.hex()
    
    return essid

def get_channel(packet) -> int:
    """
    Extract channel number from packet.
    
    Args:
        packet: Scapy packet
    
    Returns:
        int: Channel number
    """
    channel = 0
    
    for element in packet.iterfind(Dot11Elt):
        if element.ID == 3:  # Channel info element
            if element.len == 1:
                channel = ord(element.info)
    
    return channel

def get_wps_info(packet) -> str:
    """
    Extract WPS information from packet.
    
    Args:
        packet: Scapy packet
    
    Returns:
        str: WPS information if available
    """
    if not display_wps:
        return ""
    
    wps_info = ""
    
    for element in packet.iterfind(Dot11Elt):
        if element.ID == 221 and element.info.startswith(b'\x00\x50\xF2\x04'):  # WPS IE
            wps_info = "WPS"
    
    return wps_info

def parse_packet(packet) -> None:
    """
    Parse a captured packet and update the network and client databases.
    
    Args:
        packet: Scapy packet
    """
    global networks, clients, client_to_ap, essid_to_bssid, handshake_captured
    
    if not packet.haslayer(Dot11):
        return
    
    # Ignore packets without addresses
    if not hasattr(packet, 'addr2') or not packet.addr2:
        return
    
    # Filter by BSSID if specified
    if target_bssid and packet.addr2 != target_bssid and packet.addr1 != target_bssid:
        return
    
    # Process Beacon frames - discover networks
    if packet.haslayer(Dot11Beacon):
        bssid = packet.addr2
        essid = get_essid(packet)
        channel = get_channel(packet)
        max_rate = get_max_rate(packet)
        encryption, cipher, auth = parse_encryption(packet)
        wps_info = get_wps_info(packet) if display_wps else ""
        
        # Signal strength - extract from RadioTap if available
        pwr = -1
        if packet.haslayer(RadioTap):
            pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
        
        # Initialize or update network information
        if bssid not in networks:
            networks[bssid] = {
                'essid': essid,
                'channel': channel,
                'encryption': encryption,
                'cipher': cipher,
                'auth': auth,
                'pwr': pwr,
                'beacons': 1,
                'data_packets': 0,
                'data_rate': 0,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'max_rate': max_rate,
                'wps': wps_info,
                'clients': set()
            }
        else:
            networks[bssid]['beacons'] += 1
            networks[bssid]['last_seen'] = time.time()
            if pwr != -1:
                networks[bssid]['pwr'] = pwr
        
        # Update ESSID to BSSID mapping
        if essid and essid != "<length 0>":
            essid_to_bssid[essid] = bssid
    
    # Process Probe Response frames - these can also reveal network info
    elif packet.haslayer(Dot11ProbeResp):
        bssid = packet.addr2
        essid = get_essid(packet)
        channel = get_channel(packet)
        max_rate = get_max_rate(packet)
        encryption, cipher, auth = parse_encryption(packet)
        wps_info = get_wps_info(packet) if display_wps else ""
        
        # Signal strength
        pwr = -1
        if packet.haslayer(RadioTap):
            pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
        
        if bssid not in networks:
            networks[bssid] = {
                'essid': essid,
                'channel': channel,
                'encryption': encryption,
                'cipher': cipher,
                'auth': auth,
                'pwr': pwr,
                'beacons': 0,
                'data_packets': 0,
                'data_rate': 0,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'max_rate': max_rate,
                'wps': wps_info,
                'clients': set()
            }
        else:
            networks[bssid]['last_seen'] = time.time()
            if pwr != -1:
                networks[bssid]['pwr'] = pwr
        
        # A client is asking for this AP - add to clients
        client_mac = packet.addr1
        if client_mac not in clients:
            clients[client_mac] = {
                'pwr': pwr,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'packets': 1,
                'probes': set([essid]) if essid else set(),
                'associated_to': bssid,
                'lost_packets': 0,
                'rx_rate': 0,
                'tx_rate': 0
            }
        else:
            clients[client_mac]['last_seen'] = time.time()
            clients[client_mac]['packets'] += 1
            if essid:
                clients[client_mac]['probes'].add(essid)
            clients[client_mac]['associated_to'] = bssid
    
    # Process Probe Request frames - clients looking for networks
    elif packet.haslayer(Dot11ProbeReq):
        client_mac = packet.addr2
        pwr = -1
        if packet.haslayer(RadioTap):
            pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
        
        essid = get_essid(packet)
        
        if client_mac not in clients:
            clients[client_mac] = {
                'pwr': pwr,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'packets': 1,
                'probes': set([essid]) if essid else set(),
                'associated_to': "(not associated)",
                'lost_packets': 0,
                'rx_rate': 0,
                'tx_rate': 0
            }
        else:
            clients[client_mac]['last_seen'] = time.time()
            clients[client_mac]['packets'] += 1
            if essid:
                clients[client_mac]['probes'].add(essid)
    
    # Process Authentication frames - client trying to connect to AP
    elif packet.haslayer(Dot11Auth):
        if packet.addr1 in networks:  # AP is the destination
            client_mac = packet.addr2
            bssid = packet.addr1
            
            if client_mac not in clients:
                pwr = -1
                if packet.haslayer(RadioTap):
                    pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
                
                clients[client_mac] = {
                    'pwr': pwr,
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'packets': 1,
                    'probes': set(),
                    'associated_to': bssid,
                    'lost_packets': 0,
                    'rx_rate': 0,
                    'tx_rate': 0
                }
            else:
                clients[client_mac]['last_seen'] = time.time()
                clients[client_mac]['packets'] += 1
                clients[client_mac]['associated_to'] = bssid
            
            # Add client to AP's client list
            networks[bssid]['clients'].add(client_mac)
            client_to_ap[client_mac] = bssid
    
    # Process Association Request frames - client associating with AP
    elif packet.haslayer(Dot11AssoReq):
        if packet.addr1 in networks:  # AP is the destination
            client_mac = packet.addr2
            bssid = packet.addr1
            
            if client_mac not in clients:
                pwr = -1
                if packet.haslayer(RadioTap):
                    pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
                
                clients[client_mac] = {
                    'pwr': pwr,
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'packets': 1,
                    'probes': set(),
                    'associated_to': bssid,
                    'lost_packets': 0,
                    'rx_rate': 0,
                    'tx_rate': 0
                }
            else:
                clients[client_mac]['last_seen'] = time.time()
                clients[client_mac]['packets'] += 1
                clients[client_mac]['associated_to'] = bssid
            
            # Update rate information if available
            for element in packet.iterfind(Dot11EltRates):
                for rate in element.info:
                    r = (rate & 0x7F) * 0.5
                    if r > clients[client_mac]['rx_rate']:
                        clients[client_mac]['rx_rate'] = r
                    if r > clients[client_mac]['tx_rate']:
                        clients[client_mac]['tx_rate'] = r
            
            # Add client to AP's client list
            networks[bssid]['clients'].add(client_mac)
            client_to_ap[client_mac] = bssid
    
    # Process Data frames - count data packets
    elif packet.type == 2:  # Data frame
        # Update AP data packet count if this is to/from an AP we know
        if packet.addr1 in networks:
            networks[packet.addr1]['data_packets'] += 1
            networks[packet.addr1]['last_seen'] = time.time()
        
        if packet.addr2 in networks:
            networks[packet.addr2]['data_packets'] += 1
            networks[packet.addr2]['last_seen'] = time.time()
        
        # Update client packet count
        if packet.addr1 not in networks and packet.addr1 not in client_to_ap:
            # This might be a client
            if packet.addr1 not in clients:
                pwr = -1
                if packet.haslayer(RadioTap):
                    pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
                
                clients[packet.addr1] = {
                    'pwr': pwr,
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'packets': 1,
                    'probes': set(),
                    'associated_to': packet.addr2 if packet.addr2 in networks else "(not associated)",
                    'lost_packets': 0,
                    'rx_rate': 0,
                    'tx_rate': 0
                }
            else:
                clients[packet.addr1]['last_seen'] = time.time()
                clients[packet.addr1]['packets'] += 1
                if packet.addr2 in networks:
                    clients[packet.addr1]['associated_to'] = packet.addr2
                    networks[packet.addr2]['clients'].add(packet.addr1)
                    client_to_ap[packet.addr1] = packet.addr2
        
        if packet.addr2 not in networks and packet.addr2 not in client_to_ap:
            # This might be a client
            if packet.addr2 not in clients:
                pwr = -1
                if packet.haslayer(RadioTap):
                    pwr = packet[RadioTap].dBm_AntSignal if hasattr(packet[RadioTap], 'dBm_AntSignal') else -1
                
                clients[packet.addr2] = {
                    'pwr': pwr,
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'packets': 1,
                    'probes': set(),
                    'associated_to': packet.addr1 if packet.addr1 in networks else "(not associated)",
                    'lost_packets': 0,
                    'rx_rate': 0,
                    'tx_rate': 0
                }
            else:
                clients[packet.addr2]['last_seen'] = time.time()
                clients[packet.addr2]['packets'] += 1
                if packet.addr1 in networks:
                    clients[packet.addr2]['associated_to'] = packet.addr1
                    networks[packet.addr1]['clients'].add(packet.addr2)
                    client_to_ap[packet.addr2] = packet.addr1
    
    # Check for EAPOL packets (WPA handshake)
    if packet.haslayer(Dot11) and packet.type == 2:  # Data frames
        if packet.haslayer() and packet.haslayer(EAPOL):
            # This is a handshake packet
            if packet.addr1 in networks:  # AP is the recipient
                bssid = packet.addr1
                client = packet.addr2
                handshake_captured.add(bssid)
            elif packet.addr2 in networks:  # AP is the sender
                bssid = packet.addr2
                client = packet.addr1
                handshake_captured.add(bssid)

def calculate_stats() -> None:
    """Calculate statistics for networks and clients."""
    global networks
    
    current_time = time.time()
    
    # Calculate data rate for each network
    for bssid, info in networks.items():
        # Calculate packets per second over last 10 seconds
        if current_time - info['first_seen'] > 10:
            info['data_rate'] = info['data_packets'] / (current_time - info['first_seen'])
    
    # Clean up old clients (not seen in last 5 minutes)
    clients_to_remove = []
    for client_mac, client_info in clients.items():
        if current_time - client_info['last_seen'] > 300:  # 5 minutes
            clients_to_remove.append(client_mac)
    
    for client_mac in clients_to_remove:
        if client_mac in clients:
            del clients[client_mac]
        if client_mac in client_to_ap:
            bssid = client_to_ap[client_mac]
            if bssid in networks and client_mac in networks[bssid]['clients']:
                networks[bssid]['clients'].remove(client_mac)
            del client_to_ap[client_mac]

def write_to_output(packet) -> None:
    """
    Write captured packet to output files based on format.
    
    Args:
        packet: Scapy packet
    """
    global output_writers, output_format, output_file, capture_ivs
    
    if not output_file or not output_format:
        return
    
    # For IVS, only capture packets with IVs
    if capture_ivs and not packet.haslayer(Dot11WEP):
        return
    
    formats = output_format.split(',')
    
    for fmt in formats:
        fmt = fmt.strip().lower()
        
        if fmt == 'pcap' and 'pcap' in output_writers:
            output_writers['pcap'].write(packet)
        
        elif fmt == 'ivs' and 'ivs' in output_writers and packet.haslayer(Dot11WEP):
            output_writers['ivs'].write(packet)
        
        elif fmt == 'csv' and 'csv' in output_writers:
            # Append to CSV file
            if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
                bssid = packet.addr2
                if bssid in networks:
                    with open(output_writers['csv'], 'a') as f:
                        f.write(f"{time.time()},{bssid},{networks[bssid]['essid']},{networks[bssid]['channel']},"
                               f"{networks[bssid]['pwr']},{networks[bssid]['encryption']}\n")

def initialize_output_writers() -> None:
    """Initialize output file writers based on specified format."""
    global output_writers, output_format, output_file
    
    if not output_file or not output_format:
        return
    
    formats = output_format.split(',')
    
    for fmt in formats:
        fmt = fmt.strip().lower()
        
        if fmt == 'pcap':
            output_writers['pcap'] = PcapWriter(f"{output_file}.pcap", append=True, sync=True)
        
        elif fmt == 'ivs':
            output_writers['ivs'] = PcapWriter(f"{output_file}.ivs", append=True, sync=True)
        
        elif fmt == 'csv':
            csv_file = f"{output_file}.csv"
            # Create and initialize CSV file with header
            with open(csv_file, 'w') as f:
                f.write("timestamp,bssid,essid,channel,signal_strength,encryption\n")
            output_writers['csv'] = csv_file
        
        elif fmt == 'netxml':
            xml_file = f"{output_file}.netxml"
            with open(xml_file, 'w') as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write('<detection-run>\n')
            output_writers['netxml'] = xml_file
        
        elif fmt == 'kismet':
            kis_file = f"{output_file}.netxml"
            with open(kis_file, 'w') as f:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write('<k:kismet xmlns:k="http://kismetwireless.net/kismet-3.1.0">\n')
            output_writers['kismet'] = kis_file
        
        elif fmt == 'gps':
            gps_file = f"{output_file}.gps"
            with open(gps_file, 'w') as f:
                f.write("# GPS data file\n")
            output_writers['gps'] = gps_file
        
        elif fmt == 'logcsv':
            logcsv_file = f"{output_file}.log.csv"
            with open(logcsv_file, 'w') as f:
                f.write("timestamp,event_type,bssid,station,notes\n")
            output_writers['logcsv'] = logcsv_file

def sniff_packets(interface: str) -> None:
    """
    Start packet sniffing on the given interface.
    
    Args:
        interface: Wireless interface name
    """
    global stop_sniffing
    
    try:
        sniff(iface=interface, prn=lambda pkt: (parse_packet(pkt), write_to_output(pkt)), 
              store=False, stop_filter=lambda pkt: stop_sniffing)
    except Exception as e:
        logging.error(f"Error during packet sniffing: {e}")
        stop_sniffing = True

def format_elapsed_time(seconds: float) -> str:
    """
    Format elapsed time into a readable string.
    
    Args:
        seconds: Elapsed time in seconds
    
    Returns:
        str: Formatted time string (e.g., '2 min 30 s')
    """
    minutes = int(seconds // 60)
    remaining_seconds = int(seconds % 60)
    
    if minutes > 0:
        return f"{minutes} min {remaining_seconds} s"
    else:
        return f"{remaining_seconds} s"

def print_header(stdscr, width: int) -> None:
    """
    Print the header section of the display.
    
    Args:
        stdscr: Curses screen object
        width: Screen width
    """
    global start_time, current_channel, handshake_captured
    
    elapsed = time.time() - start_time
    elapsed_str = format_elapsed_time(elapsed)
    current_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # Prepare handshake status string
    handshake_str = ""
    if handshake_captured:
        first_bssid = next(iter(handshake_captured))
        if first_bssid in networks:
            handshake_str = f"[ WPA handshake: {first_bssid} ]"
    
    # Print the header line
    header = f" CH {current_channel} ][ Elapsed: {elapsed_str} ][ {current_date} {handshake_str}"
    stdscr.addstr(0, 0, header[:width])
    stdscr.addstr(1, 0, " " * width)  # Empty line

def print_network_header(stdscr, row: int, width: int) -> int:
    """
    Print the network section header.
    
    Args:
        stdscr: Curses screen object
        row: Current row
        width: Screen width
    
    Returns:
        int: Next row
    """
    header = " BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID"
    stdscr.addstr(row, 0, header[:width])
    return row + 1

def print_networks(stdscr, row: int, width: int, max_rows: int) -> int:
    """
    Print network information.
    
    Args:
        stdscr: Curses screen object
        row: Current row
        width: Screen width
        max_rows: Maximum rows to display
    
    Returns:
        int: Next row
    """
    global networks, target_bssid
    
    # Sort networks by signal strength (PWR)
    sorted_networks = sorted(networks.items(), key=lambda x: x[1].get('pwr', -999), reverse=True)
    
    # If target BSSID is specified, only show that network
    if target_bssid:
        sorted_networks = [(bssid, info) for bssid, info in sorted_networks if bssid == target_bssid]
    
    # Limit to available rows
    display_count = min(len(sorted_networks), max_rows)
    
    for i in range(display_count):
        if row >= curses.LINES - 1:
            break
        
        bssid, info = sorted_networks[i]
        essid = info.get('essid', '')
        pwr = info.get('pwr', -1)
        rxq = 0  # Receive quality - not accurately calculated in this implementation
        beacons = info.get('beacons', 0)
        data_packets = info.get('data_packets', 0)
        data_rate = info.get('data_rate', 0)
        channel = info.get('channel', 0)
        max_rate = info.get('max_rate', 0)
        encryption = info.get('encryption', 'OPN')
        cipher = info.get('cipher', '')
        auth = info.get('auth', '')
        
        # Format the line
        line = f" {bssid}  {pwr:3d} {rxq:3d}  {beacons:7d}  {data_packets:7d} {data_rate:4.1f}  {channel:2d}  {max_rate:3.0f}  {encryption:4s} {cipher:6s} {auth:4s} {essid}"
        stdscr.addstr(row, 0, line[:width])
        row += 1
    
    return row

def print_client_header(stdscr, row: int, width: int) -> int:
    """
    Print the client section header.
    
    Args:
        stdscr: Curses screen object
        row: Current row
        width: Screen width
    
    Returns:
        int: Next row
    """
    header = " BSSID              STATION            PWR   Rate   Lost  Packets  Notes  Probes"
    stdscr.addstr(row, 0, header[:width])
    return row + 1

def print_clients(stdscr, row: int, width: int, max_rows: int) -> int:
    """
    Print client information.
    
    Args:
        stdscr: Curses screen object
        row: Current row
        width: Screen width
        max_rows: Maximum rows to display
    
    Returns:
        int: Next row
    """
    global clients, target_bssid
    
    # Sort clients by signal strength (PWR)
    sorted_clients = sorted(clients.items(), key=lambda x: x[1].get('pwr', -999), reverse=True)
    
    # If target BSSID is specified, only show clients for that AP
    if target_bssid:
        sorted_clients = [(mac, info) for mac, info in sorted_clients 
                         if info.get('associated_to') == target_bssid]
    
    # Limit to available rows
    display_count = min(len(sorted_clients), max_rows)
    
    for i in range(display_count):
        if row >= curses.LINES - 1:
            break
        
        mac, info = sorted_clients[i]
        bssid = info.get('associated_to', '(not associated)')
        pwr = info.get('pwr', -1)
        rx_rate = info.get('rx_rate', 0)
        tx_rate = info.get('tx_rate', 0)
        lost = info.get('lost_packets', 0)
        packets = info.get('packets', 0)
        notes = ""  # Additional notes would go here
        probes = ", ".join(list(info.get('probes', set()))[:2])  # Show first 2 probes
        
        # Format the line
        line = f" {bssid}  {mac}  {pwr:3d}   {rx_rate:2.0f}-{tx_rate:2.0f}    {lost:4d}   {packets:6d}  {notes:5s}  {probes}"
        stdscr.addstr(row, 0, line[:width])
        row += 1
    
    return row

def update_display(stdscr) -> None:
    """
    Update the display with current network and client information.
    
    Args:
        stdscr: Curses screen object
    """
    global networks, clients, screen_width, current_channel
    
    # Get screen dimensions
    max_y, max_x = stdscr.getmaxlines(), stdscr.getmaxyx()[1]
    screen_width = max_x
    
    # Clear screen
    stdscr.clear()
    
    # Print header
    print_header(stdscr, max_x)
    
    # Calculate available rows for networks and clients
    available_rows = max_y - 6  # 2 for header, 2 for network header, 2 for client header
    network_rows = min(len(networks), available_rows // 2)
    client_rows = available_rows - network_rows
    
    row = 3  # Start after header
    
    # Print networks section
    row = print_network_header(stdscr, row, max_x)
    row = print_networks(stdscr, row, max_x, network_rows)
    
    # Add a blank line
    if row < max_y - 1:
        stdscr.addstr(row, 0, " " * max_x)
        row += 1
    
    # Print clients section
    if row < max_y - 2:  # Ensure there's space for the header and at least one row
        row = print_client_header(stdscr, row, max_x)
        row = print_clients(stdscr, row, max_x, client_rows)
    
    # Refresh the screen
    stdscr.refresh()

def display_loop(stdscr) -> None:
    """
    Main display loop.
    
    Args:
        stdscr: Curses screen object
    """
    global stop_sniffing, screen_width
    
    # Initialize colors
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_BLUE, -1)
    
    # Hide cursor
    curses.curs_set(0)
    
    # Don't wait for key input
    stdscr.nodelay(True)
    
    # Get screen dimensions
    screen_width = stdscr.getmaxyx()[1]
    
    # Main loop
    while not stop_sniffing:
        try:
            # Check for key presses
            key = stdscr.getch()
            if key == ord('q'):
                stop_sniffing = True
                break
            
            # Update statistics
            calculate_stats()
            
            # Update the display
            update_display(stdscr)
            
            # Wait a bit before refreshing again
            time.sleep(0.5)
            
        except KeyboardInterrupt:
            stop_sniffing = True
            break
        except Exception as e:
            logging.error(f"Error in display loop: {e}")
            time.sleep(1)

def close_output_writers() -> None:
    """Close all output file writers."""
    global output_writers
    
    for fmt, writer in output_writers.items():
        if fmt == 'pcap' or fmt == 'ivs':
            # Close Scapy writers
            writer.close()
        elif fmt in ('netxml', 'kismet'):
            # Close XML files with proper ending
            with open(writer, 'a') as f:
                if fmt == 'netxml':
                    f.write('</detection-run>\n')
                else:
                    f.write('</k:kismet>\n')

def signal_handler(sig, frame) -> None:
    """Handle interrupt signals."""
    global stop_sniffing
    stop_sniffing = True
    print("\nStopping capture...")
    sys.exit(0)

def main() -> None:
    """Main function to start the wireless monitoring tool."""
    global stop_sniffing, interface, target_bssid, target_channel
    global capture_ivs, display_wps, output_format, output_file
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Wireless Network Monitoring Tool')
    parser.add_argument('interface', help='Wireless interface to use (must be in monitor mode)')
    parser.add_argument('--bssid', help='Filter by BSSID (MAC address of AP)')
    parser.add_argument('-c', '--channel', type=int, help='Set channel for scanning')
    parser.add_argument('--ivs', action='store_true', help='Save only captured IVs')
    parser.add_argument('--wps', action='store_true', help='Display WPS information')
    parser.add_argument('-o', '--output-format', help='Output format (pcap, ivs, csv, gps, kismet, netxml, logcsv)')
    parser.add_argument('-w', '--write', help='Write output to specified file prefix')
    
    args = parser.parse_args()
    
    # Set global variables from arguments
    interface = args.interface
    target_bssid = args.bssid
    target_channel = args.channel
    capture_ivs = args.ivs
    display_wps = args.wps
    output_format = args.output_format
    output_file = args.write
    
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('wireless_monitor.log'), logging.StreamHandler()]
    )
    
    # Check if the interface exists
    if interface not in conf.ifaces:
        logging.error(f"Interface {interface} not found. Available interfaces: {', '.join(conf.ifaces.keys())}")
        sys.exit(1)
    
    # Set monitor mode
    if not set_monitor_mode(interface):
        logging.error(f"Failed to set monitor mode on {interface}")
        sys.exit(1)
    
    # Initialize output writers if output format specified
    if output_format and output_file:
        initialize_output_writers()
    
    # Start channel hopper thread if no specific channel is set
    if not target_channel:
        hopper_thread = threading.Thread(target=channel_hopper, args=(interface,))
        hopper_thread.daemon = True
        hopper_thread.start()
    
    # Start packet sniffer thread
    sniffer_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    try:
        # Start curses UI
        curses.wrapper(display_loop)
    except KeyboardInterrupt:
        pass
    finally:
        # Clean up when done
        stop_sniffing = True
        close_output_writers()
        logging.info("Monitoring stopped.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
