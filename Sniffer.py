import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
sock.bind(("0.0.0.0", 0))

print("Packet Sniffer started. Listening for ICMP packets...")

while True:
        packet, addr = sock.recvfrom(65535)
        print(f"Packet received from {addr}")
        print(packet)
