SPY - Packet Sniffer built with Python, PyQt5 for the GUI, and Scapy for network packet manipulation.

Features:
1. Real-time Sniffing: Capture and display network packets in real time.
2. Protocol Filtering: Filter displayed packets by protocol: All, TCP, UDP, ICMP, and ARP.
3. Dark Theme: A sleek, console-inspired dark interface for comfortable viewing.
4. Packet Details: Click on any packet in the list to open a detailed view of its layers and fields (powered by Scapy's show(dump=True)).
5. Multi-threading: Uses a separate thread for the sniffing process to keep the GUI responsive.
