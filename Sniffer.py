import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QPushButton, QListWidget, QListWidgetItem,
    QHBoxLayout, QDialog, QLabel, QComboBox
)
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QPalette
from scapy.all import sniff, ARP, IP, TCP, UDP
from threading import Thread


class Communicator(QObject):
    new_packet = pyqtSignal(str)


class PacketSniffer(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("SPY - Packet Sniffer")
        self.setGeometry(100, 100, 700, 500)

        self.set_dark_theme()

        self.layout = QVBoxLayout()

        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["All", "TCP", "UDP", "ICMP", "ARP"])
        self.protocol_filter.currentIndexChanged.connect(self.update_filter)
        self.style_combobox(self.protocol_filter)
        self.layout.addWidget(self.protocol_filter)

        self.listwidget = QListWidget()
        self.listwidget.setFont(QFont("Consolas", 11))
        self.layout.addWidget(self.listwidget)

        self.style_scrollbars()

        self.button_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.style_button(self.start_button)
        self.button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.style_button(self.stop_button)
        self.button_layout.addWidget(self.stop_button)

        self.layout.addLayout(self.button_layout)

        self.setLayout(self.layout)

        self.sniffing = False
        self.communicator = Communicator()
        self.communicator.new_packet.connect(self.display_packet)

        self.packets = []
        self.protocol_filter_value = "All"

        self.listwidget.itemClicked.connect(self.show_packet_details)

    def set_dark_theme(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor("#121212"))
        palette.setColor(QPalette.WindowText, QColor("#FFFFFF"))
        palette.setColor(QPalette.Base, QColor("#1E1E1E"))
        palette.setColor(QPalette.Text, QColor("#00FF7F"))
        self.setPalette(palette)

        #css design
    def style_button(self, button):
        button.setStyleSheet("""
            QPushButton {
                background-color: #333;
                color: #fff;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)

    def style_combobox(self, combobox):
        combobox.setStyleSheet("""
            QComboBox {
                background-color: black;
                color: white;
                border: 1px solid white;
                padding: 5px;
            }
            QComboBox QAbstractItemView {
                background-color: black;
                color: white;
            }
        """)

    def style_scrollbars(self):
        self.listwidget.verticalScrollBar().setStyleSheet("""
            QScrollBar:vertical {
                background: black;
                width: 10px;
            }
        """)
        self.listwidget.horizontalScrollBar().setStyleSheet("""
            QScrollBar:horizontal {
                background: black;
                height: 10px;
            }
        """)

    def update_filter(self):
        self.protocol_filter_value = self.protocol_filter.currentText()

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.thread = Thread(target=self.sniff_packets)
            self.thread.daemon = True
            self.thread.start()

    def stop_sniffing(self):
        self.sniffing = False

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if self.sniffing:
            self.packets.append(packet)
            summary = self.format_summary(packet)

            if summary:
                self.communicator.new_packet.emit(summary)

    def format_summary(self, packet):
        proto_name = "UNKNOWN"

        if ARP in packet:
            proto_name = "ARP"
            if self.protocol_filter_value not in ["All", "ARP"]:
                return None
            op = packet[ARP].op
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            if op == 1:
                return f"ARP Request: Who has {dst_ip}? Tell {src_ip}"
            elif op == 2:
                return f"ARP Reply: {src_ip} is at {packet[ARP].hwsrc}"

        elif IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            proto_name = proto_map.get(proto, f"Protocol {proto}")

            if self.protocol_filter_value not in ["All", proto_name]:
                return None

            if TCP in packet or UDP in packet:
                sport = packet.sport
                dport = packet.dport
                return f"{src}:{sport} → {dst}:{dport} | {proto_name}"
            else:
                return f"{src} → {dst} | {proto_name}"

        return None

    def display_packet(self, text):
        scrollbar = self.listwidget.verticalScrollBar()
        at_bottom = scrollbar.value() == scrollbar.maximum()

        item = QListWidgetItem(text)
        self.listwidget.addItem(item)

        if at_bottom:
            self.listwidget.scrollToBottom()

    def show_packet_details(self, item):
        index = self.listwidget.row(item)
        packet = self.packets[index]

        details_window = QDialog(self)
        details_window.setWindowTitle("Packet Details")
        details_window.setGeometry(150, 150, 500, 400)

        layout = QVBoxLayout()
        details_text = packet.show(dump=True)
        label = QLabel(details_text)
        label.setWordWrap(True)
        layout.addWidget(label)

        details_window.setLayout(layout)
        details_window.exec_()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSniffer()
    window.show()
    sys.exit(app.exec_())
