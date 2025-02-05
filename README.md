# Device Discovery and Port Scanning Script

## Description
This script is designed to perform device discovery within a local area network (LAN) and to check the status of various ports on each identified device. It serves as a valuable tool for security auditing and network diagnostics, allowing users to assess the connectivity and security posture of devices on their network.

## Features
The script includes several essential features:
- **Router Detection**: Verifies whether the provided IP address corresponds to a router (default gateway) or a local machine, enabling the user to understand the network layout better.
- **Active Device Scanning**: Progressively scans the network to identify which devices are currently active, providing a comprehensive list of reachable IP addresses.
- **Port Scanning**: Checks for open ports on each active IP address, helping identify potential vulnerabilities in devices.
- **Multiprocessing Optimization**: Uses multiprocessing techniques to enhance performance, allowing it to scan multiple devices and ports concurrently, thereby reducing overall execution time.

## Technologies Used
The implementation of the script is based on the following technologies:
- **Python 3**: The programming language used for writing the script, known for its simplicity and versatility.
- **Key Modules**:
  - `argparse`: For parsing command-line arguments.
  - `socket`: For handling network connections.
  - `subprocess`: For executing system commands.
  - `multiprocessing`: For parallel processing capabilities.
  - `ipaddress`: For managing and manipulating IP addresses efficiently.

## Installation
To set up the script on your machine, follow these steps:
1. Ensure that Python is installed on your device. You can download it from the [official Python website](https://www.python.org/).
2. Clone or download the repository containing the script files.
3. No external libraries are required; the script depends solely on Python's standard library modules.

## How to Use
To execute the script, provide the IP address of the host that you wish to analyze. The command is structured as follows:

```sh
python script.py -i <IP>
```

For example, to scan the IP address `192.168.1.1`, you would use:

```sh
python script.py -i 192.168.1.1
```

## Sample Output
Upon execution, the script provides output detailing the scanning process:

```
Scanning network for devices in the same range as 192.168.1.1.

Found IPs:
192.168.1.2
192.168.1.3

Scanning ports for IP: 192.168.1.2
Scanning ports for IP: 192.168.1.3

Open ports found:
IP: 192.168.1.2, Open Port: 22
IP: 192.168.1.3, Open Port: 80
```

This output includes the active IP addresses that were discovered, as well as the open ports found on each device.

## Considerations
- **Administrator Permissions**: It may be necessary to run the script with elevated permissions to achieve optimal results, particularly on systems that enforce strict access controls.
- **Operating System Compatibility**: The script is optimized for use on Linux systems, as it relies on specific commands like `ip route` and `ping -c`, which may not function as intended on other operating systems.
- **Legal Compliance**: Users should ensure they have the necessary permissions to perform network scans to avoid potential legal ramifications. Unauthorized scanning of networks can lead to serious consequences.

## License
This project is distributed under the **MIT License**, permitting users to utilize, modify, and distribute the software while ensuring proper attribution.

