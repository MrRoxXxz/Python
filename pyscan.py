import os
import subprocess
import time
import sys
import webbrowser
import importlib
from datetime import datetime
import json
import pyshark
import docx
import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
from ipaddress import ip_network, ip_address

# Required modules
REQUIRED_MODULES = ['pyshark', 'python-docx', 'networkx', 'matplotlib']

def install_missing_modules():
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            print(f"Installing missing module: {module}")
            subprocess.run([sys.executable, '-m', 'pip', 'install', module])

install_missing_modules()

def search_tool(tool_name, path):
    for root, dirs, files in os.walk(path):
        if tool_name in files:
            return os.path.join(root, tool_name)
    return None

def install_and_check_tool(tool_name, install_url):
    tool_path = search_tool(tool_name, "C:\\Program Files\\Wireshark")
    if not tool_path:
        print(f"{tool_name} not found. Downloading...")
        webbrowser.open(install_url)
        input(f"Install {tool_name} manually and press Enter once done.")
        tool_path = search_tool(tool_name, "C:\\")
        if not tool_path:
            print(f"{tool_name} installation failed.")
            sys.exit(1)
    return tool_path

def list_interfaces():
    dumpcap_path = install_and_check_tool("dumpcap.exe", "https://www.wireshark.org/download.html")
    print("Available network interfaces:")
    subprocess.run([dumpcap_path, "-D"])

def capture_traffic(interface, duration, filesize, output_file):
    dumpcap_path = install_and_check_tool("dumpcap.exe", "https://www.wireshark.org/download.html")
    
    # Get current timestamp for folder name
    timestamp = datetime.now().strftime("%H%M%S_%m%d%y")
    output_folder = f"pcap_{timestamp}"
    
    # Create the folder if it doesn't exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    # Define output file path
    output_file_path = os.path.join(output_folder, f"{output_file}.pcapng")
    
    # Capture traffic and store it in the timestamped folder
    subprocess.run([dumpcap_path, "-i", interface, "-a", f"duration:{duration}", "-b", f"filesize:{filesize}", "-w", output_file_path])
    
    # Wait a few seconds to ensure file is written
    time.sleep(2)
    
    # Check if the folder contains the captured file
    if not os.listdir(output_folder):
        print(f"No PCAP files were written to {output_folder}. Please check your capture settings.")
        return None, timestamp  # Return the timestamp as well
    
    print(f"Files captured in folder: {output_folder}")
    return output_folder, timestamp  # Return both folder path and timestamp

def merge_pcaps(timestamp):
    # Use the timestamp passed from capture_traffic
    output_folder = f"pcap_{timestamp}"
    
    # Ensure the folder exists
    if not os.path.exists(output_folder):
        print(f"The folder {output_folder} does not exist.")
        return None
    
    # Find all .pcapng files in the folder
    pcapng_files = [os.path.join(output_folder, f) for f in os.listdir(output_folder) if f.endswith(".pcapng")]
    
    # Check if there are PCAPNG files to merge
    if len(pcapng_files) > 1:
        merged_file = input("Enter merged file name (without .pcapng): ")
        mergecap_path = r"C:\Program Files\Wireshark\mergecap.exe"  # Update this path if necessary
        
        # Run mergecap with the correct arguments
        subprocess.run([mergecap_path, "-F", "pcapng", "-w", os.path.join(output_folder, f"{merged_file}.pcapng")] + pcapng_files)
        
        print(f"PCAP files merged into {os.path.join(output_folder, f'{merged_file}.pcapng')}")
        return os.path.join(output_folder, f"{merged_file}.pcapng")
    elif pcapng_files:
        print(f"Only one PCAP file found: {pcapng_files[0]}")
        return pcapng_files[0]  # Return the single PCAP if there's only one
    else:
        print(f"No PCAPNG files found in {output_folder}.")
        return None

def analyze_pcap(filepath):
    cap = pyshark.FileCapture(filepath)
    packet_data = []
    
    for packet in cap:
        data = {}
        
        # Check for 'frame' layer before extracting attributes
        if hasattr(packet, 'frame'):
            data["frame.time_utc"] = getattr(packet.frame, "time", None)
            data["frame.len"] = getattr(packet.frame, "len", None)
            data["frame.protocols"] = getattr(packet.frame, "protocols", None)
        
        # Extract Ethernet details if available
        if hasattr(packet, 'eth'):
            data["eth.dst"] = getattr(packet.eth, "dst", None)
            data["eth.dst_resolved"] = getattr(packet.eth, "dst_resolved", None)
            data["eth.addr"] = getattr(packet.eth, "addr", None)
            data["eth.src"] = getattr(packet.eth, "src", None)
            data["eth.src_resolved"] = getattr(packet.eth, "src_resolved", None)
        
        # Extract IP details if available
        if hasattr(packet, 'ip'):
            data["ip.src"] = getattr(packet.ip, "src", None)
            data["ip.dst"] = getattr(packet.ip, "dst", None)
        
        # Extract TCP details if available
        if hasattr(packet, 'tcp'):
            data["tcp.srcport"] = getattr(packet.tcp, "srcport", None)
            data["tcp.dstport"] = getattr(packet.tcp, "dstport", None)
        
        # Add the data to the packet_data list
        packet_data.append(data)
    
    # Save the parsed data to a JSON file
    output_json = filepath.replace(".pcapng", ".json")
    with open(output_json, "w") as f:
        json.dump(packet_data, f, indent=4)

    print(f"Parsed data saved to {output_json}")
    return output_json  # Return the path to the JSON file


def create_network_graph(json_file):
    # Create a graph
    G = nx.Graph()

    # Load data from the JSON file
    with open(json_file, "r") as f:
        packet_data = json.load(f)
    
    for packet in packet_data:
        # Extract relevant data from the packet
        src_ip = packet.get("ip.src")
        dst_ip = packet.get("ip.dst")
        src_mac = packet.get("eth.src")
        dst_mac = packet.get("eth.dst")
        src_port = packet.get("tcp.srcport")
        dst_port = packet.get("tcp.dstport")
        
        if src_ip and dst_ip:
            # Add nodes for IPs and MAC addresses
            G.add_node(src_ip, label=src_mac)
            G.add_node(dst_ip, label=dst_mac)

            # Add edges for communication (IP-MAC) and optionally ports
            if src_port and dst_port:
                edge_label = f"{src_port}->{dst_port}"
                G.add_edge(src_ip, dst_ip, label=edge_label)
            else:
                G.add_edge(src_ip, dst_ip)

    return G

def plot_network_graph_interactive(G, output_folder, output_file):
    # Create a pyvis Network object
    net = Network(notebook=True, height="800px", width="100%")

    # Add nodes and edges to the network
    for node in G.nodes:
        net.add_node(node, label=node)
    
    for u, v, data in G.edges(data=True):
        edge_label = data.get('label', '')  # Using 'label' for the edge, if available
        net.add_edge(u, v, label=edge_label)

    # Set the options as valid JSON
    net.set_options(""" 
    var options = {
        "nodes": {
            "shape": "dot",
            "size": 10
        },
        "edges": {
            "smooth": {
                "type": "continuous"
            },
            "arrows": {
                "to": {
                    "enabled": true,
                    "scaleFactor": 1
                }
            }
        },
        "physics": {
            "enabled": true,
            "barnesHut": {
                "gravitationalConstant": -2000,
                "springLength": 95
            }
        }
    }
    """)

    # Generate the output HTML file
    output_path = os.path.join(output_folder, f"{output_file}_network.html")
    net.show(output_path)
    print(f"Network diagram saved to {output_path}")


from ipaddress import ip_network, ip_address
import json

def extract_matching_ips(json_file, subnet):
    """Extract IPs from the JSON file that match the given subnet."""
    matching_ips = []
    processed_ips = set()  # Set to track already processed IPs

    with open(json_file, 'r') as file:
        packets = json.load(file)
        
        for packet in packets:
            ip_src = packet.get("ip.src")
            ip_dst = packet.get("ip.dst")

            # Check if either source or destination IP matches the subnet and hasn't been processed
            if ip_src and ip_src not in processed_ips and ip_in_subnet(ip_src, subnet):
                matching_ips.append(ip_src)
                processed_ips.add(ip_src)

            if ip_dst and ip_dst not in processed_ips and ip_in_subnet(ip_dst, subnet):
                matching_ips.append(ip_dst)
                processed_ips.add(ip_dst)

    return matching_ips

def ip_in_subnet(ip, subnet):
    """Check if an IP address is in the specified subnet."""
    ip_obj = ip_address(ip)  # Convert the string to an IPv4Address object
    network = ip_network(subnet, strict=False)  # Convert subnet to IPv4Network object
    
    # Check if the IP address is in the subnet
    return ip_obj in network

def run_nmap_scan(ip_list_file, output_file):
    """Run Nmap scan on the IP list and output to file."""
    
    # Define the path to the Nmap executable
    NMAP_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"  # Update with your actual Nmap installation path
    
    command = [
        NMAP_PATH, "-T3", "-p-", "-v", "-iL", ip_list_file, "-oN", output_file
    ]
    
    print(f"Running Nmap with command: {' '.join(command)}")
    
    try:
        # Run the Nmap scan and write output in real-time
        with open(output_file, 'w') as f_out:
            process = subprocess.Popen(command, stdout=f_out, stderr=subprocess.PIPE)

            # Log the stderr in real-time
            for line in process.stderr:
                print(line.decode(), end="")
                
            process.wait()  # Wait for the Nmap process to finish
            if process.returncode == 0:
                print(f"Nmap scan completed successfully. Output saved to {output_file}")
            else:
                print(f"Nmap scan failed with return code {process.returncode}")
                
    except subprocess.TimeoutExpired:
        print(f"Nmap scan timed out after 600 seconds.")
    except subprocess.CalledProcessError as e:
        print(f"Nmap scan failed with error code {e.returncode}.")
        print(f"Error details: {e.stderr.decode()}")
    except Exception as e:
        print(f"An unexpected error occurred while running Nmap: {str(e)}")

def main():
    # Step 1: List interfaces and get selected interface
    list_interfaces()
    interface = input("Enter network interface: ")
    
    # Step 2: Capture traffic and save to timestamped folder
    duration = input("Enter capture duration (seconds): ")
    filesize = input("Enter buffer filesize (KB): ")
    output_file = input("Enter output filename (do not add .pcapng): ")

    output_folder, timestamp = capture_traffic(interface, duration, filesize, output_file)
    
    # Check if capture was successful
    if output_folder is None:
        print("Capture failed. Exiting.")
        return
    
    # Step 3: Merge PCAP files if there are multiple
    merged_pcap = merge_pcaps(timestamp)
    
    if merged_pcap:
        # Step 4: Analyze the merged PCAP and generate JSON
        json_file = analyze_pcap(merged_pcap)

        # Step 5: Create and plot the interactive network graph
        G = create_network_graph(json_file)
        plot_network_graph_interactive(G, output_folder, output_file)
        
        # Step 6: Run Nmap scan after network graph creation
        subnet = input("Enter the subnet (e.g., 192.168.1.0/24): ")
        ip_list_file = os.path.join(output_folder, "matching_ips.txt")  # IP list file
        nmap_output = os.path.join(output_folder, "nmap_results.txt")  # Nmap results file
        
        # Extract matching IPs from the JSON file based on subnet
        matching_ips = extract_matching_ips(json_file, subnet)
        
        if matching_ips:
            # Write matching IPs to the file
            with open(ip_list_file, 'w') as f:
                for ip in matching_ips:
                    f.write(f"{ip}\n")
            print(f"Matching IPs saved to {ip_list_file}")
            
            print(f"Running Nmap scan on the IPs from {ip_list_file}...")
            run_nmap_scan(ip_list_file, nmap_output)  # Run the Nmap scan in real-time
        else:
            print(f"No IPs found matching the subnet {subnet}. Nmap scan aborted.")
    else:
        print("No PCAPNG files found. Exiting.")

if __name__ == "__main__":
    main()
