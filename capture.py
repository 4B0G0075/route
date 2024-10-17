import pyshark
import asyncio
from routes import app


# 全域變數儲存封包數據
packets_data = []
capture_thread = None
capture_running = False

def extract_packet_info(packet):
    src_ip = dst_ip = protocol = src_port = dst_port = length = 'N/A'
    
    if 'IP' in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        length = packet.ip.len
        protocol = packet.ip.proto

    if 'TCP' in packet:
        src_port = packet.tcp.srcport
        dst_port = packet.tcp.dstport
    elif 'UDP' in packet:
        src_port = packet.udp.srcport
        dst_port = packet.udp.dstport

    return src_ip, dst_ip, protocol, length, src_port, dst_port

def capture_packets():
    interface = 'Adapter for loopback traffic capture'  # 替換為適合你的系統的接口名稱
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface, display_filter='http')
    
    global packets_data, capture_running
    for packet in capture.sniff_continuously():
        if not capture_running:
            break
        src_ip, dst_ip, protocol, length, src_port, dst_port = extract_packet_info(packet)
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'length': length,
            'src_port': src_port,
            'dst_port': dst_port
        }
        packets_data.append(packet_info)
        if len(packets_data) > 100:  # 限制存儲的封包數量
            packets_data.pop(0)

