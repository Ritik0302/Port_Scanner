import socket
import os
from scapy.all import ARP, Ether, srp

color_start = "\033[{}m".format(31)
color_end = "\033[0m"
logo='''
                              
      .=*%@@@@@#+:            
    :#@*         %@+          
   *@+            -%%.        
  +@+-@# #@+ @@- @%.@@.       
  @@ -@@ @@@ @@@ @% =@=       
  @@ -@@@@@@@@@@@@# =@+       
  #@-  -@@@@@@@@%   %@:       
   %@-   =@@@@%   .#@-        
    =@%=.       :*@#-*-.      
      =#@%#**#%@%+-+@@@@%-    
         .::::.    =@@@@@@#:  
                    -%@@@@@@. 
                      -%@@@+  
                              
'''
print(color_start+logo+color_end)

def grab_banner(ip, port):
    """
    Attempt to grab the banner from a service running on the target IP and port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception as e:
        return None

def perform_os_detection(target):
    """
    Perform basic OS detection based on open ports and services.
    """

    known_services = {
        22: 'SSH',        
        80: 'HTTP',       
        445: 'SMB',       
        3389: 'RDP',      
    }
    
    
    os_guess = 'Unknown'
    for port in known_services:
        if port in known_services:
            os_guess = 'Linux/Unix' if known_services[port] in ['SSH', 'HTTP'] else 'Windows'
            break
    
    return os_guess

def get_mac_address(ip):
    """
    Get the MAC address for the given IP address using ARP.
    """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv.hwsrc
    return 'Unknown'

def port_scan(target, start_port, end_port):
    results = []

    print(f"Scanning {target} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))

            if result == 0:
                state = "open"
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = "Unknown"

               
                banner = grab_banner(target, port)
                if banner:
                    version = banner.split('\n')[0]  
                else:
                    version = "Unknown"

                results.append((port, state, service, version))

            sock.close()
        except KeyboardInterrupt:
            print("Scan interrupted by user")
            break
        except socket.error as err:
            print(f"Could not connect to {target}:{port} due to {err}")
            break

    
    os_info = perform_os_detection(target)
   
    mac_address = get_mac_address(target)

    print_results(results, os_info, mac_address)

def print_results(results, os_info, mac_address):
    if not results:
        print("No open ports found.")
    else:
        print("{:<10} {:<10} {:<15} {:<}".format("Port", "State", "Service", "Version"))
        print("-" * 50)
        for port, state, service, version in results:
            print("{:<10} {:<10} {:<15} {:<}".format(port, state, service, version))
    
    print("\nOS Information: ", os_info)
    print("MAC Address: ", mac_address)

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    start_port = int(input("Enter start port: "))
    end_port = int(input("Enter end port: "))
    port_scan(target, start_port, end_port)
