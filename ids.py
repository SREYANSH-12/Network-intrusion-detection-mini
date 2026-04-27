from scapy.all import sniff

def detect(packet):
    if packet.haslayer("TCP"):
        flags = packet["TCP"].flags
        if flags == "S":
            print(f"[ALERT] Possible SYN Scan from {packet['IP'].src}")

def main():
    print("Starting IDS...")
    sniff(prn=detect, store=0)

if __name__ == "__main__":
    main()
