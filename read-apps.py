#!/usr/bin/env python

import sys
import os
import ipaddress
from datetime import datetime

pcap_file = sys.argv[1]


with open(pcap_file, "rb") as f:
    block_type = 1
    while block_type != 0:
        block_type = int.from_bytes(f.read(4), byteorder="little")
        block_len = int.from_bytes(f.read(4), byteorder="little")
        if block_type == int.from_bytes(b"\xAD\x0B\x00\x40", byteorder="little"):
            left = block_len - 12
            print(f"block_len: {block_len} (0x{block_len:x})")
            pen = int.from_bytes(f.read(4), byteorder="little")
            print(f"pen: {pen:x}")
            while left > 7:
                app_len = int.from_bytes(f.read(1), byteorder="little")
                left = left - 1
                print(f"app_len: {app_len}")
                app_name = f.read(app_len)
                left = left - app_len
                print(f"app_name: {app_name}")
                records = int.from_bytes(f.read(4), byteorder="little")
                left = left - 4
                print(f"records: {records}")
                for i in range(records):
                    ip_version = int.from_bytes(f.read(1), byteorder="little")
                    left = left - 1
                    print(f"ip_version: {ip_version}")
                    if ip_version == 4:
                        local_ip = int.from_bytes(f.read(4), byteorder="big")
                        left = left - 4
                        print(f"local_ip: {ipaddress.IPv4Address(local_ip)}")
                    else:
                        local_ip = int.from_bytes(f.read(8), byteorder="big")
                        left = left - 8
                        print(f"local_ip: {ipaddress.IPv6Address(local_ip)}")
                    local_port = int.from_bytes(f.read(2), byteorder="little")
                    left = left - 2
                    print(f"local_port: {local_port}")
                    proto = int.from_bytes(f.read(1), byteorder="little")
                    left = left - 1
                    if proto == 6:
                        print(f"proto: TCP")
                    elif proto == 17:
                        print(f"proto: UDP")
                    else:
                        print(f"proto: {proto}")
                    start_time = int.from_bytes(f.read(8), byteorder="little") * (10 ** -6)
                    left = left - 8
                    print(f"start_time: {datetime.fromtimestamp(start_time)}")
                    end_time = int.from_bytes(f.read(8), byteorder="little") * (10 ** -6)
                    left = left - 8
                    print(f"end_time: {datetime.fromtimestamp(end_time)}")


            f.read(left % 4)
            left = left % 4

            block_end_len = int.from_bytes(f.read(4), byteorder="little")
            left = left - 4
            print(f"block_end_len: {block_end_len} (0x{block_end_len:x})")
        else:
            f.seek(block_len - 8, 1)
