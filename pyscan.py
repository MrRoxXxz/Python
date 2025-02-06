import os
import subprocess
import time
import sys
import webbrowser

# Function to recursively search for dumpcap.exe
def search_dumpcap(path):
    for root, dirs, files in os.walk(path):
        if "dumpcap.exe" in files:
            dumpcap_path = os.path.join(root, "dumpcap.exe")
            return dumpcap_path
    return None

# Function to recursively search for tshark.exe
def search_tshark(path):
    for root, dirs, files in os.walk(path):
        if "tshark.exe" in files:
            tshark_path = os.path.join(root, "tshark.exe")
            return tshark_path
    return None

# Function to install Wireshark directly
def install_direct():
    print("Installing Wireshark directly...")
    url = "https://2.na.dl.wireshark.org/win64/Wireshark-4.4.3-x64.exe"
    subprocess.run(["start", url], shell=True)  # Opens the installer in the browser

# Function to open the Wireshark download page in the browser
def open_browser():
    print("Opening the Wireshark download page in your browser...")
    webbrowser.open("https://www.wireshark.org/download.html")

# Function to check and install Wireshark if needed
def install_and_check_tool(tool, install_func, tool_name, tool_path_search_func):
    tool_path = tool_path_search_func("C:\\Program Files\\Wireshark")
    if not tool_path:
        tool_path = tool_path_search_func("C:\\")
    
    if not tool_path:
        print(f"{tool_name} not found.")
        install_choice = input(f"Would you like to install {tool_name} directly? (Y/N): ").strip().upper()
        
        if install_choice == 'Y':
            install_func()
            time.sleep(10)  # Wait a bit for the installation to start, adjust if needed
            tool_path = tool_path_search_func("C:\\")
            
            if tool_path:
                print(f"{tool_name} installed successfully.")
                return tool_path
            else:
                print(f"{tool_name} installation failed or was not detected.")
                sys.exit(1)
        elif install_choice == 'N':
            open_browser_choice = input(f"Would you like to open a browser to manually install {tool_name}? (Y/N): ").strip().upper()
            if open_browser_choice == 'Y':
                open_browser()
                input(f"Please install {tool_name} manually and press Enter once done.")
                tool_path = tool_path_search_func("C:\\")
                
                if tool_path:
                    print(f"{tool_name} installed successfully.")
                    return tool_path
                else:
                    print(f"{tool_name} installation failed or was not detected.")
                    sys.exit(1)
            else:
                print("You chose not to install Wireshark. Exiting.")
                sys.exit(1)
        else:
            print("Invalid input, exiting.")
            sys.exit(1)
    return tool_path

# Main function to run the program
def main():
    # Check and install dumpcap if needed
    dumpcap_path = install_and_check_tool("dumpcap.exe", install_direct, "dumpcap.exe", search_dumpcap)
    
    # Add dumpcap.exe to system path
    os.environ["PATH"] += os.pathsep + os.path.dirname(dumpcap_path)
    print("Dumpcap.exe path added to system path.\n")
    
    # Seperator
    print('-' * 90)
    print('-' * 30+" Select your network interface " +'-' * 30)
    print('-' * 90)
    print()
    
    def get_interfaces():
        """This function displays dumpcap's network interface options"""
        subprocess.run(["dumpcap", "-D"])
    
    # Get user input for network interface name
    get_interfaces()
    interface_number = input("Enter the number of the network interface you want to use: ")
    interface = subprocess.run(["c:\\program files\\wireshark\\dumpcap.exe", "-D"], capture_output=True).stdout.decode().strip().split("\n")[int(interface_number)-1].split(' ')[1]
    
    # Seperator
    print('-' * 90)
    print('-' * 33+" Set your scan duration " +'-' * 33)
    print('-' * 90)
    print()
    
    # Get user input for autostop duration
    duration = input("Enter the autostop duration (in seconds): ")
    
    # Seperator
    print('-' * 90)
    print('-' * 31+" Set your file buffer size " +'-' * 32)
    print('-' * 90)
    print()
    
    # Get user input for buffer filesize
    filesize = input("Enter the buffer filesize (in KB): ")
    
    # Seperator
    print('-' * 90)
    print('-' * 31+" Set your output file name " +'-' * 32)
    print('-' * 90)
    print()
    
    # Get user input for output filename
    pcap_filename = input("Enter the output filename: ")
    
    # Seperator
    print('-' * 90)
    print('-' * 29+" Scanning your network interface " +'-' * 28)
    print('-' * 90)
    print()
    
    # Run dumpcap command
    subprocess.run(["c:\\program files\\wireshark\\dumpcap.exe", "-i", interface, "-a", "duration:"+duration, "-b", "filesize:"+filesize, "-w", pcap_filename+".pcapng"])
    
    # Wait for Dumpcap to complete
    current_dir = os.getcwd()
    pcapng_files = []
    # Search through current directory and subdirectories
    for root, dirs, files in os.walk(current_dir):
        for file in files:
            if file.endswith('.pcapng'):
                pcapng_files.append(os.path.join(root, file))
    
    # Ask user if they would like to run mergecap before merging
    print('-' * 90)
    print('-' * 29+" Run Mergecap to combine PCAPS " +'-' * 30)
    print('-' * 90)
    print()
    
    answer = input("Would you like to run mergecap to combine the pcaps (yes/no): ")
    
    if answer.lower() == "yes":
        mergedfile = input('enter merged file name "(do not include .pcapng)": ')
        subprocess.run(["mergecap", "-F", "pcapng", "-w", mergedfile+".pcapng"] + pcapng_files)
    
    # Ask if they want to use tshark for conversion
    print('-' * 90)
    print('-' * 27+" Run TSHARK to convert pcap to json " +'-' * 27)
    print('-' * 90)
    
    # Check and install tshark if needed
    tshark_path = install_and_check_tool("tshark.exe", install_direct, "tshark.exe", search_tshark)
    
    # Ask user if they would like to run tshark before converting the merged file to json format
    answer = input("Would you like to run tshark before converting the merged file to json format? (yes/no): ")
    
    # Use tshark to convert the merged pcapng file to json
    print ("Please run: '" + tshark_path + " -T json -r FILE.pcapng > FILE.json' from the Command line")

if __name__ == "__main__":
    main()
