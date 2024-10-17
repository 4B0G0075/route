import time
import pyshark
import asyncio
from routes import app



packet_data = []  # 用於存儲原始封包數據
traffic_data = []  # 用於存儲流量數據 (Kbps)


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

    return {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'length': length,
        'src_port': src_port,
        'dst_port': dst_port
    }

def capture_packets():
    """捕獲封包並計算流量"""
    interface = 'Adapter for loopback traffic capture'  # 替換為適合你的系統的接口名稱
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface, display_filter='http')
    
    global packets_data, capture_running
    capture_running = True
    while True:
            start_time = time.time()
            byte_count = 0

            # 捕獲10個封包進行計算
            for packet in capture.sniff_continuously(packet_count=10):
                packet_info = extract_packet_info(packet)  # 提取封包信息
                packet_data.append(packet_info)  # 保存提取後的封包信息
                byte_count += int(packet.length) if hasattr(packet, 'length') else 0

            calculate_traffic(byte_count, start_time)  # 計算流量

def calculate_traffic(byte_count, start_time):
    """計算流量並儲存到 traffic_data"""
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        bytes_per_second = byte_count / elapsed_time
        kbps = (bytes_per_second * 8) / 1000  # 轉換為 Kbps
        traffic_data.append(kbps)

        # 保持 traffic_data 只保留最近的 60 秒數據
        if len(traffic_data) > 60:
            traffic_data.pop(0)