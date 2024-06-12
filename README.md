# CodeAlpha_Basic_Network_Sniffer
Task 1 in CodeAlpha's Cyber Security Internship 

## OverView

This Python script serves as a network sniffer, capable of capturing and analyzing network traffic. It provides insights into how data flows across a network and how network packets are structured.


## Requirements

- Python 3.x
- Scapy library (`pip install scapy`)
- Npcap  (Nmap Packet Capture Library) or WinPcap but less preferrable
- textwrap 

## Usage

1. <b>Clone the repository</b>: <br>
git clone [https://github.com/salma-h-wagdy/CodeAlpha_Basic_Network_Sniffer](https://github.com/salma-h-wagdy/CodeAlpha_Basic_Network_Sniffer)

2. <b>Install dependencies</b>: <br>
    pip install -r requirements.txt
3. <b> Run the script </b>

## Features

- **Packet Capture**: Utilizes the Scapy library to capture network packets in real-time.
- **Packet Analysis**: Parses captured packets to extract and display relevant information such as Ethernet frame details, IPv4 packet details (including ICMP, TCP, and UDP), etc.
- **Error Handling**: Implements robust error handling mechanisms using try-except blocks to gracefully handle exceptions that may occur during packet processing or sniffing.
- **Customization**: Easily customizable with options to configure capture timeout, output format, and more.
  
## Notes:
- Adjust the `TIMEOUT` constant in the script to change the capture timeout duration.
- Customize the output format and packet processing logic as needed.

