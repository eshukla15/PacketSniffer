# 🕵️‍♂️ Windows Raw Packet Sniffer

> A low-level Python network packet sniffer built using raw sockets on Windows to understand about tools like wireshark and to gain knowledge about ports and ip addressing.
Sniff. Slice. Analyze.

---

## 🔍 What is this?

This is a **minimal Python-based packet sniffer** that captures **IPv4 packets** directly from your network interface using **raw sockets**. It parses IP headers and dives deep into **ICMP**, **TCP**, and **UDP** protocols — showing you how the internet talks under the hood.

**Think of it like Wireshark's lightweight cousin** — but written in pure Python.

---

## ✨ What makes it effective

- Sniffs **raw IP packets** directly from your machine.
- Parses IP headers, and dives into ICMP, TCP, and UDP payloads.
- Shows TCP flags like SYN, ACK, PSH, etc.
- Prints all this cleanly and in real-time.
- **Built for Windows**, which is often tricky for raw socket access.

---

## 💡 Why only for Windows?

This project uses:

```python
socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
```


These are Windows-only socket APIs.
Linux uses AF_PACKET, but Windows hides Ethernet (MAC layer) data — giving access only to the IP layer. So this tool is tailored for that environment.

## 🛠️ How to Use

### ✅ Requirements
- Python 3.8+
- **Must run as Administrator** (raw sockets require elevated privileges)
- Platform: **Windows only** 

### 📦 Install Python Dependencies

This script uses only the built-in `socket`, `struct`, and `textwrap` modules — no external dependencies needed.

### 🚀 Run the Sniffer

```bash
python demo.py
```

## 📚 Theory

I was looking into ports, so basically in a computer, there are two types of ports, physical ones, to connect cables, and network ones, which are like a virtual path to communicate
for example, another machine wants to communicate with us, it will contact us through my ip address, that will refer to my machine, and my port number will tell me what type of service it is and will work on that
to be more clear, let a client send a request to server, ip address will refer to the machine and port will tell if it is a http request or smtp request or ftp request, these services already reserve the ports
some companies or well known ports are fixed, i.e. for better communication or easiness, nodejs has fixed its port, reactjs has fixed its port, 2^16 ports = 65535 ports
if two apps use same port, one will have to end task, for example two online video call apps
now, as an ethical hacker we need to at least assign our service to a unique port to work properly


🔹 Well-Known Ports (0–1023)

| Port | Protocol / Service       | Transport | Description                    |
| ---- | ------------------------ | --------- | ------------------------------ |
| 20   | FTP (Data)               | TCP       | File Transfer (Data Channel)   |
| 21   | FTP (Control)            | TCP       | File Transfer Protocol         |
| 22   | SSH                      | TCP       | Secure Shell for remote login  |
| 23   | Telnet                   | TCP       | Insecure remote login          |
| 25   | SMTP                     | TCP       | Sending email                  |
| 53   | DNS                      | UDP/TCP   | Domain name resolution         |
| 67   | DHCP (Server)            | UDP       | Dynamic IP assignment          |
| 68   | DHCP (Client)            | UDP       | Receives IP configuration      |
| 69   | TFTP                     | UDP       | Simple file transfer           |
| 80   | HTTP                     | TCP       | Web traffic (unencrypted)      |
| 110  | POP3                     | TCP       | Receive email (old)            |
| 119  | NNTP                     | TCP       | Network News Transfer Protocol |
| 123  | NTP                      | UDP       | Time synchronization           |
| 135  | Microsoft RPC            | TCP/UDP   | Remote Procedure Call          |
| 137  | NetBIOS Name Service     | UDP       | Windows name resolution        |
| 138  | NetBIOS Datagram Service | UDP       | Windows file/printer sharing   |
| 139  | NetBIOS Session Service  | TCP       | Windows file/printer sharing   |
| 143  | IMAP                     | TCP       | Receive email (modern)         |
| 161  | SNMP                     | UDP       | Network monitoring             |
| 162  | SNMP Trap                | UDP       | Asynchronous notifications     |
| 179  | BGP                      | TCP       | Border Gateway Protocol        |
| 443  | HTTPS                    | TCP       | Secure web traffic             |
| 445  | SMB                      | TCP       | Windows file sharing           |
| 514  | Syslog                   | UDP       | Logging system messages        |
| 587  | SMTP (with TLS)          | TCP       | Sending secure email           |
| 993  | IMAP over SSL            | TCP       | Secure email receive           |
| 995  | POP3 over SSL            | TCP       | Secure email receive           |


🔹 Registered Ports (1024–49151)
Used by user processes or applications:

| Port | Protocol / Service             |
| ---- | ------------------------------ |
| 1433 | Microsoft SQL Server           |
| 1521 | Oracle DB                      |
| 3306 | MySQL                          |
| 3389 | RDP (Remote Desktop)           |
| 5432 | PostgreSQL                     |
| 5900 | VNC                            |
| 6379 | Redis                          |
| 8080 | HTTP Alternate (common in dev) |
| 8443 | HTTPS Alternate                |


🔹 Dynamic/Private Ports (49152–65535)
Used for temporary client-side ports
Chosen randomly when your device connects to a service.


This sniffer inspects and parses the most common internet protocols:

### 📦 IPv4 Header
| Field          | Size    | Description                    |
| -------------- | ------- | ------------------------------ |
| Version        | 4 bits  | Always `4` for IPv4            |
| IHL            | 4 bits  | Header length                  |
| TTL            | 1 byte  | Time to live (prevents loops)  |
| Protocol       | 1 byte  | ICMP(1), TCP(6), UDP(17), etc. |
| Source/Dest IP | 4 bytes | Who sent it, where it's going  |

### 📨 ICMP (Ping, Traceroute)
| Field    | Description                 |
| -------- | --------------------------- |
| Type     | Echo Request (8), Reply (0) |
| Code     | More specific message info  |
| Checksum | Error-checking              |

### 🔄 TCP (Reliable Streams)
| Field       | Description                  |
| ----------- | ---------------------------- |
| Ports       | Source & destination         |
| Seq/Ack     | Byte tracking                |
| Flags       | SYN, ACK, PSH, RST, URG, FIN |
| Data Offset | Where actual data starts     |

### 🚀 UDP (Fast, Connectionless)
| Field    | Description             |
| -------- | ----------------------- |
| Ports    | Source & destination    |
| Length   | Length of entire packet |
| Checksum | Error-checking          |


## ⚠️ Disclaimer
This project is intended for educational purposes only.
Do not use it on networks you do not own or have explicit permission to analyze.


## 👨‍💻 Author
Built by @eshukla15 — created for learning the art of packet-level analysis with Python on Windows.
Feel free to fork, enhance, or port it to Linux!


