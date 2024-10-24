import time
import pyshark
import asyncio
import datetime

# 用於存儲封包和流量數據
packet_data = []  # 儲存原始封包數據，僅保留最近 1 分鐘
traffic_data = []  # 儲存流量數據 (Kbps)
capture_running = False

def extract_packet_info(packet):
    """提取封包信息"""
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

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 將封包信息返回
    return {
        'timestamp': timestamp,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'length': length,
        'src_port': src_port,
        'dst_port': dst_port
    }

def capture_packets():
    """捕獲封包並計算流量"""
    interface = '乙太網路'  # 替換為適合你的系統的接口名稱
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.LiveCapture(interface=interface)
    global capture_running
    capture_running = True

    byte_count = 0
    start_time = time.time()

    try:
        while capture_running:
            # 捕獲封包並計算數據
            for packet in capture.sniff_continuously():
                if not capture_running:
                    break

                # 提取封包信息並存儲
                packet_info = extract_packet_info(packet)
                packet_data.append(packet_info)

                # 清理多餘的封包數據
                if len(packet_data) > 120000:
                    packet_data.pop(0)

                # 計算封包的總字節數
                byte_count += int(packet_info['length']) if packet_info['length'].isdigit() else 0

                # 檢查是否過了一秒
                if time.time() - start_time >= 1:
                    # 計算流量並重置計算參數
                    calculate_traffic(byte_count, start_time)
                    byte_count = 0
                    start_time = time.time()

    except Exception as e:
        print(f"Error capturing packets: {e}")
    finally:
        capture.close()

def calculate_traffic(byte_count, start_time):
    """計算流量並儲存到 traffic_data，每秒更新一次"""
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        bytes_per_second = byte_count / elapsed_time
        kbps = (bytes_per_second * 8) / 1000  # 轉換為 Kbps
        traffic_data.append(kbps)

        # 保持 traffic_data 只保留最近的 600 秒數據
        if len(traffic_data) > 600:
            traffic_data.pop(0)
