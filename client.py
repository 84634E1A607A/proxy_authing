import ipaddress
import time
import hashlib
import argparse
import os
import re
import socket
import psutil
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# We use UDP port 67 (DHCP Server) to send data packets. The channel is single-directional
# As for authentication, we use asymmetric encryption. The client sends a request packet encrypted with a certain
# pubkey identified by clientid. The server decrypts the packet and verifies the data. If the data is valid, the server
# executes proxy auth command.
# The data contains a timestamp, client's IP address.
# Magic cookie to identify this as custom protocol
YIADDR = b'\xfe\x4e\x08\xce'


def pesudo_random(b: bytes) -> int:
    return (int.from_bytes(hashlib.sha256(b).digest()[5:9], 'little') >> 13) & 0xf


def construct_dhcp_request_packet(ip_address: ipaddress.IPv4Address,
                                  server_address: ipaddress.IPv4Address,
                                  client_identifier: bytes,
                                  pubkey: rsa.RSAPublicKey) -> bytes:
    assert len(client_identifier) == 4, 'Client identifier must be 4 bytes'

    packet = b''

    packet += b'\x01'  # Request OP
    packet += b'\x01'  # Hardware Type
    packet += b'\x10'  # Hardware Address Length, 16 bytes
    packet += b'\x00'  # Hops
    tid = os.urandom(4)  # Transaction ID
    packet += tid
    packet += b'\x00\x00'  # Seconds Elapsed
    packet += b'\x00\x00'  # Bootp Flags
    packet += b'\x00\x00\x00\x00'  # Client IP
    packet += YIADDR  # Your IP
    packet += server_address.packed  # Server IP
    packet += b'\x00\x00\x00\x00'  # Gateway IP

    uuid = os.urandom(16)

    # Based on tid, we embed the client identifier into the uuid field
    start_byte = pesudo_random(tid)
    if start_byte > 12:
        uuid = client_identifier[start_byte-12:] + uuid[start_byte-12:start_byte] + client_identifier[:start_byte-12]
    else:
        uuid = uuid[:start_byte] + client_identifier + uuid[start_byte+4:]

    packet += uuid  # Client Hardware Address

    plain_data = b''
    plain_data += ip_address.packed
    timestamp = int(time.time() * 1000).to_bytes(8, 'little')
    plain_data += timestamp

    # Treat pubkey as rsa pubkey and use it to encrypt the data
    encrypted_data: bytes = pubkey.encrypt(plain_data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    # 192 bytes left here
    packet += 64 * b'\x00'  # Padding
    packet += encrypted_data

    packet += b'\x63\x82\x53\x63'  # Magic Cookie

    return packet


parser = argparse.ArgumentParser()
parser.add_argument('--clientfile', type=str, required=True)
parser.add_argument('--server', type=str, required=True)
parser.add_argument('--client-ip-range', type=str, action='append')
args = parser.parse_args()

clientid = os.path.basename(args.clientfile).split('.')[0]
if not re.match(r'^[0-9a-f]{8}$', clientid):
    raise ValueError('Invalid client id')

clientid = bytes.fromhex(clientid)

with open(args.clientfile, encoding="latin-1") as f:
    pubkey = serialization.load_der_public_key(bytes.fromhex(f.read()))

if not re.match(r'^\d+\.\d+\.\d+\.\d+$', args.server):
    print(f"Trying to resolve IP address for server {args.server}")
    args.server = socket.gethostbyname(args.server)

if args.client_ip_range is not None:
    client_nw = [ipaddress.IPv4Network(x) for x in args.client_ip_range]
else:
    client_nw = [ipaddress.IPv4Network('0.0.0.0/0')]

packets = []
# Enumerate all network interfaces and find IP address
for interface, addrs in psutil.net_if_addrs().items():
    for addr in addrs:
        if addr.family == socket.AF_INET:
            ip_address = ipaddress.IPv4Address(addr.address)
            if any([ip_address in nw for nw in client_nw]):
                break
    else:
        continue

    print(f"Found IP address {ip_address} on interface {interface}")
    p = construct_dhcp_request_packet(ipaddress.IPv4Address(ip_address), ipaddress.IPv4Address(args.server), clientid, pubkey)
    packets.append(p)

if len(packets) == 0:
    raise ValueError('No suitable IP address found')

# Use udp to send the packet to the server port 67
print(f"Sending packet to {args.server}:67")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for p in packets:
    sock.sendto(p, (args.server, 67))
