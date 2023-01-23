import os
import subprocess
import time
import sys

                   
# Function to recursively search for dumpcap.exe
def search_dumpcap(path):
    for root, dirs, files in os.walk(path):
        if "dumpcap.exe" in files:
            dumpcap_path = os.path.join(root, "dumpcap.exe")
            return dumpcap_path
    return None
    
# Search for dumpcap.exe in the default location
dumpcap_path = search_dumpcap("C:\\Program Files\\Wireshark")

# If not found, search recursively
if not dumpcap_path:
    dumpcap_path = search_dumpcap("C:\\")

# If dumpcap.exe is not found
if not dumpcap_path:
    print("dumpcap.exe not found.")
    sys.exit(1)
    
# Add dumpcap.exe to system path
os.environ["PATH"] += os.pathsep + os.path.dirname(dumpcap_path)
print("Dumpcap.exe path added to system path.")

print()

#Seperator
print('-' * 90)
print('-' * 30+" Select your network interace " +'-' * 30)
print('-' * 90)

print()
 
def get_interfaces():
    """This function displays dumpcap's network interface options"""
    subprocess.run(["dumpcap", "-D"])
    

# Get user input for network interface name
get_interfaces()
interface_number = input("Enter the number of the network interface you want to use: ")
interface = subprocess.run(["c:\\program files\\wireshark\\dumpcap.exe", "-D"], capture_output=True).stdout.decode().strip().split("\n")[int(interface_number)-1].split(' ')[1]

print()

#Seperator
print('-' * 90)
print('-' * 33+" Set your scan duration " +'-' * 33)
print('-' * 90)

print()

# Get user input for autostop duration
duration = input("Enter the autostop duration (in seconds): ")

print()

#Seperator
print('-' * 90)
print('-' * 31+" Set your file buffer size " +'-' * 32)
print('-' * 90)

print()

# Get user input for buffer filesize
filesize = input("Enter the buffer filesize (in KB): ")

print()

#Seperator
print('-' * 90)
print('-' * 31+" Set your output file name " +'-' * 32)
print('-' * 90)

print()

# Get user input for output filename
pcap_filename = input("Enter the output filename: ")

print()

#Seperator
print('-' * 90)
print('-' * 29+" Scanning your network interface " +'-' * 28)
print('-' * 90)

print()

# Run dumpcap command
subprocess.run(["c:\\program files\\wireshark\\dumpcap.exe", "-i", interface, "-a", "duration:"+duration, "-b", "filesize:"+filesize, "-w", pcap_filename+".pcapng"])

print()

#Wait for Dumpcap to complete
#time.sleep(int(duration)+1)

# Get current directory
current_dir = os.getcwd()
# Initialize empty list to store .pcapng files
pcapng_files = []
# Search through current directory and subdirectories
for root, dirs, files in os.walk(current_dir):
    for file in files:
        if file.endswith('.pcapng'):
            pcapng_files.append(os.path.join(root, file))

print('-' * 90)
print('-' * 29+" Run Mergecap to combine PCAPS " +'-' * 30)
print('-' * 90)

print()

# Ask user if they would like to run mergecap before merging
answer = input("Would you like to run mergecap to combine the pcaps (yes/no): ")

print()

if answer.lower() == "yes":
    mergedfile = input('enter merged file name "(do not include .pcapng)": ')
# Use mergecap to merge all pcapng files
subprocess.run(["mergecap", "-F", "pcapng", "-w", mergedfile+".pcapng"] + pcapng_files)

print()

print('-' * 90)
print('-' * 27+" Run TSHARK to convert pcap to json " +'-' * 27)
print('-' * 90)

print()

# Function to recursively search for tshark.exe
def search_tshark(path):
    for root, dirs, files in os.walk(path):
        if "tshark.exe" in files:
            tshark_path = os.path.join(root, "tshark.exe")
            return tshark_path
    return None
    
# Search for tshark.exe in the default location
tshark_path = search_tshark("C:\\Program Files\\Wireshark")

# If not found, search recursively
if not tshark_path:
    tshark_path = search_tshark("C:\\")

# If tshark.exe is not found
if not  tshark_path:
    print("tshark.exe not found.")
    sys.exit(1)
    
# Add tshark.exe to system path
os.environ["PATH"] += os.pathsep + os.path.dirname(tshark_path)
print("tshark.exe path added to system path.")

# Ask user if they would like to run tshark before converting
answer = input("Would you like to run tshark before converting the merged file to json format? (yes/no): ")

#if answer.lower() == "yes":
#merged = input('enter json file name "(do not include .json)": ')
print()

print('-' * 90)
print('-' * 22+" TSHARK Error: Please manually run TSHARK.exe " +'-' * 22)
print('-' * 90)

print()

# Use tshark to convert the merged pcapng file to json
# Use tshark to convert the merged pcapng file to json
print ("Please run: '" + tshark_path + " -T json -r FILE.pcapng > FILE.json' from the Command line")
