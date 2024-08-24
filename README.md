# Port_Scanner
![Port_Scanner Landing Page](https://github.com/Ritik0302/Port_Scanner/blob/main/Screenshot_2024-08-23_21_19_34.jpg?raw=true)


**Port_Scanner** is a tool designed for educational purposes. This tool is created to be user-friendly and demonstrates the use of Python dictionaries along with essential modules for network manipulation.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Modules Required](#modules-required)
- [Disclaimer](#disclaimer)

## Installation

To run this tool, you need to have Python installed on your system. Additionally, you must install three main Python modules: `socket`, `scapy` and `os`. You can install these modules using pip:

```sh
pip install scapy
```
Remaining modules are pre-installed so don't need to install it manually

## Usage

Clone the Repository: If you haven't already, clone the repository to your local machine:
```sh
git clone https://github.com/yourusername/your-repository.git
```

Navigate to the Script Directory:
```sh
cd your-repository
```
Run the Script: Execute the script with Python:
```sh
python port_scanner.py
```
Follow the Prompts: The script will prompt you to enter the target IP address or hostname, as well as the range of ports to scan. Example input:

plaintext

Enter target IP or hostname: 192.168.1.1
Enter start port: 1
Enter end port: 1024

## Notes
    Permissions: Ensure you have the necessary permissions to scan the target network.
    Firewalls: Some firewalls might block or interfere with the scanning process.
    Error Handling: The script includes basic error handling for common issues such as connection problems and interruptions.

## Modules Required
This tool relies on the following Python modules:

scapy: Used for network packet crafting and sending.

## Disclaimer
This tool is intended solely for educational purposes. Unauthorized use of this tool on networks you do not own or have explicit permission to test is illegal and unethical. Use this tool responsibly.

Author: Ritik Singhania
Contact: ritiksinghania0302@gmail.com
