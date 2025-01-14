import ipaddress
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

YIADDR = b'\xfe\x4e\x08\xce'


privkey_dict = {}
timestamp_dict = {}


def pesudo_random(b: bytes) -> int:
    return (int.from_bytes(hashlib.sha256(b).digest()[5:9], 'little') >> 13) & 0xf


def decode_dhcp_request_packet(packet: bytes) -> ipaddress.IPv4Address:
    assert len(packet) == 240, 'Invalid packet length'
    assert packet[0] == 1, 'Invalid OP code'
    assert packet[1] == 1, 'Invalid Hardware Type'
    assert packet[2] == 16, 'Invalid Hardware Address Length'
    assert packet[3] == 0, 'Invalid Hops'
    tid = packet[4:8]
    assert packet[8:10] == b'\x00\x00', 'Invalid Seconds Elapsed'
    assert packet[10:12] == b'\x00\x00', 'Invalid Bootp Flags'
    assert packet[12:16] == b'\x00\x00\x00\x00', 'Invalid Client IP'
    assert packet[16:20] == YIADDR, 'Invalid Your IP'
    server_ip = ipaddress.IPv4Address(packet[20:24])
    assert packet[24:28] == b'\x00\x00\x00\x00', 'Invalid Gateway IP'
    client_hwaddr = packet[28:44]

    start_byte = pesudo_random(tid)
    if start_byte > 12:
        client_identifier = client_hwaddr[start_byte:] + client_hwaddr[:start_byte-12]
    else:
        client_identifier = client_hwaddr[start_byte:start_byte+4]

    if client_identifier not in privkey_dict:
        raise ValueError('Client not registered')

    encrypted_data = packet[-132:-4]
    plain_data = privkey_dict[client_identifier].decrypt(encrypted_data, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

    ip_address = ipaddress.IPv4Address(plain_data[:4])
    timestamp = int.from_bytes(plain_data[4:], 'little')

    if timestamp <= timestamp_dict.get(client_identifier, 0):
        raise ValueError('Invalid timestamp')

    timestamp_dict[client_identifier] = timestamp
    return ip_address


pkb = bytes.fromhex("3082025d02010002818100d430675773fcbf543546e4d28d169eae9f6a650dac151dbdf385333e80d9a47536d2fbe3208e56219f2c414e3f45e77e080ca34d0f61cfa46d73ee9cd24ff54791d48feb435f39ca7184a8330d1416ee9686660fc10a983a19e08afd9c259c9f41e63ac3e5f1bf72fc007476a2967ee45cb2df69129ddb80efe28f0cf7024d3b020301000102818100a3cee258cf4015ecca5c7a965939573373fa4d1d2af5fa4a044f9669f04b14fd305fdcf950ced18b8f38390a512a8435f5bcdbecc7ad3901b545c4b5e85eb5f92bb50c4b2d5b83fe66b8b13c5e23068ad734a2e8ffb892d6e7fd050de2f9f8407557e0ffba78883823f07b4747b96e989cde95e6fc80c85c05170df012ae91f1024100fad9647cd0bd5fc4cfe3d7bc948be35fac3f099b78a0064bec4641bc76b9bdffad801408a6eff8a5cef6d49bb1352ffcb40dba16472f5c1fce71b3438aaf087f024100d88bca981a40b1e859e9f5d46a77f74153fe1a7ed07a96394b05706f04db4d699a53d7c7671476dca88bdc1c0eff418e84300694ea4c5197ee97f9f551d17d450240558618c495467b8856788fed33981e05586c859204264aff47a70c727ce806e74cf805dc8d4df3b05447c364f19df8a6679ce67d01f81ba89c72177447ac3571024100d3492a86d86eb167fd7b2b527403d3abd95140f6e56206fba5f88ba8b73b674017c5a0efbde318cada658481981c7511a266ddb5251b0c2dcb2e5c4481ed7e650240744cea59d8853ce0f474f2bfc6656efae6dfc5d89cb5345be8eb2450691b6579973bad4748219967a11817427f9549f6829c4c964e12fb9b0ef47bb45eaf4011")
pk = serialization.load_der_private_key(pkb, None)
p = bytes.fromhex("01011000a6a99eb90000000000000000fe4e08cec0a8010100000000616aebdfa54375688e01020304bafeed000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001251f1ae98dd5c9c355038d207b412b24d6af147fbe18f582d250bbf62f9fa6785241b892814619743ce5c7baf6670ef0ab10a96f094329bb87cd16501c34bb61b0578ed7068b7fd8a0584712c59105905963bd54157d621818ed2a2bc16bef0a8e91e3c892e419fefc6c4a25b614499603a3308af2cc2b0da70de1f5581b98063825363")

privkey_dict[b'\x01\x02\x03\x04'] = pk

print(decode_dhcp_request_packet(p))
