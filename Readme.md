# ZNet Scanner v2.1.0

ZNet Scanner is an enhanced Java-based network scanning tool designed for accurate discovery and analysis of devices on a local network. It intelligently identifies the network segment, discovers active devices using multiple techniques, resolves hostnames asynchronously, performs concurrent port scanning, identifies device vendors via MAC lookup, performs basic security checks, monitors for ARP anomalies, and allows exporting results for further analysis.

<p align="center">
  <img src="https://github.com/user-attachments/assets/8221a933-3b60-4126-b7b6-ed065c011667" alt="Screenshot_20241228_102517" width=400>
</p>


## Key Features

*   **Accurate Network Selection**: Prompts user to select the network interface to scan if multiple are detected.
*   **Intelligent Subnet Scanning**: Calculates the correct IP range based on the selected interface's subnet mask, not just assuming /24.
*   **Improved Host Discovery**: Uses both ICMP pings and TCP probes (to common ports) to detect active hosts, increasing reliability when ICMP is blocked.
*   **Comprehensive Device Information**: Retrieves IP address, MAC address, and attempts asynchronous hostname resolution (doesn't block scanning).
*   **MAC Vendor Identification**: Looks up the device manufacturer based on the MAC address's OUI using an `oui.txt` file.
*   **Concurrent Port Scanning**: Scans a predefined list of common TCP ports on discovered devices concurrently for faster results per host.
*   **Security Assessment**: Flags devices with commonly exposed/insecure ports open (e.g., Telnet, RDP, SMB). *Note: This is a basic check, not a full vulnerability scan.*
*   **ARP Spoofing Detection**: Monitors the system's ARP cache periodically for suspicious changes (e.g., MAC changes for known IPs, duplicate MACs). *Note: This is a basic detection mechanism.*
*   **Export Results**: Allows exporting the discovered device information (IP, Hostname, MAC, Vendor, Ports, Issues, Timestamp) to CSV or JSON files.
*   **Detailed Logging**: Provides real-time logging of scan progress, device discoveries, errors, and ARP alerts.
*   **Cross-Platform**: Built with Java Swing for GUI compatibility (requires `arp` command availability for MAC/ARP features).

## Getting Started

### Prerequisites

*   **Java Development Kit (JDK)**: Version 11 or higher recommended (due to newer language features and APIs used).
*   **Gson Library**: Google's JSON library is required for the JSON export feature. Download the JAR (e.g., `gson-2.10.1.jar`) from Maven Central or the Gson GitHub page.
*   **`arp` Command**: The standard `arp` command-line tool must be available and executable on the system PATH. (Included by default on most Windows, Linux, macOS systems).
*   **`oui.txt` File**: A MAC address vendor lookup file (Organizationally Unique Identifier).
    *   Download a copy (search for "oui.txt download" or get one from Wireshark resources).
    *   Place the `oui.txt` file in the classpath (e.g., in the `src` directory when compiling/running from source, or inside the final JAR).

### Installation & Running

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/jeninsutradhar/znet-scanner.git
    cd znet-scanner
    ```

2.  **Place Dependencies:**
    *   Download the Gson JAR (e.g., `gson-2.10.1.jar`) and place it in a `lib` directory inside the `znet-scanner` folder (`znet-scanner/lib/gson-2.10.1.jar`).
    *   Place the `oui.txt` file in the `src` directory (`znet-scanner/src/oui.txt`).

3.  **Compile:**
    (Ensure your `javac` command corresponds to JDK 11+)
    ```bash
    # Adjust path to gson jar if necessary
    # On Linux/macOS:
    javac -cp "lib/gson-2.10.1.jar:src" src/NetworkScanner.java -d bin
    # On Windows:
    # javac -cp "lib/gson-2.10.1.jar;src" src/NetworkScanner.java -d bin
    ```
    *(This compiles the source files into a `bin` directory)*

4.  **Run:**
    ```bash
    # Ensure oui.txt is accessible via the classpath (src is included here)
    # On Linux/macOS:
    java -cp "lib/gson-2.10.1.jar:src:bin" NetworkScanner
    # On Windows:
    # java -cp "lib\gson-2.10.1.jar;src;bin" NetworkScanner
    ```


## Dependencies

*   **Gson**: Used for exporting results to JSON format. ([Google Gson](https://github.com/google/gson))
*   **`oui.txt`**: External data file required for MAC address to vendor lookup.

## Limitations & Disclaimer

*   **Basic Security Checks**: The "Potential Issues" feature only checks for the presence of commonly known ports. It **does not** perform actual vulnerability scanning or exploit checking. It is **not** a substitute for dedicated security auditing tools.
*   **Basic ARP Monitoring**: The ARP spoofing detection relies on periodic polling of the system `arp` command output. Sophisticated attackers might evade this simple check. It provides a basic level of awareness, not guaranteed protection.
*   **Platform Dependency**: MAC address retrieval and ARP monitoring depend on the standard `arp` command-line utility and parsing its output, which might vary slightly between OS versions or distributions.
*   **Host Discovery**: While improved, host discovery can still miss devices configured to block all forms of network probes (ICMP and TCP).
*   **Performance**: Scanning very large subnets (/16, etc.) may take significant time and resources.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request with a clear description of your improvements.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
```

---
