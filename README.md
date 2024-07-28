# UDP-Fragment-Sender
A powerful network testing tool designed for advanced protocol analysis and stress testing. This Go-based utility enables the generation and transmission of customized UDP packet fragments with spoofed source IP addresses.

## Features

- Sends fragmented UDP packets
- Uses randomized source IP addresses
- Customizable fragment size
- Configurable number of packet sets to send

## Prerequisites

- Go programming language
- Root/administrator privileges (required for raw socket operations)

## Usage

```
go run udp-frag-sender.go <destination_ip> <destination_port> <loop_count> [fragment_size]
```

- `destination_ip`: The IP address of the target
- `destination_port`: The port number on the target
- `loop_count`: Number of packet sets to send
- `fragment_size` (optional): Size of each fragment in bytes (default: 1480)

## Example

```
sudo go run udp-frag-sender.go 192.168.1.100 8080 5 1000
```

This command will send 5 sets of fragmented packets to 192.168.1.100 on port 8080, with each fragment sized at 1000 bytes.

## Notes

- This program requires root/administrator privileges to run due to its use of raw sockets.
- The program generates valid random source IP addresses for each packet set.
- A small random delay (0-100ms) is added between sending each fragment.
- The program adheres to IPv4 standards and avoids using reserved or private IP ranges as source addresses.

## Disclaimer

This tool is intended for legitimate network testing and analysis purposes only. Misuse of this tool may violate laws or network policies. Use responsibly and only on networks you have permission to test.
