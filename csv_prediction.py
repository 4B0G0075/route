from flask import Flask, request, render_template
import chardet
import os
import dpkt
import csv
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score
from datetime import datetime
from collections import defaultdict, deque
import socket
from routes import app


def allowed_file(filename):
    return '.' in filename

def convert_pcap_to_csv(input_file):
    output_csv = os.path.join(app.config['UPLOAD_FOLDER'], 'output.csv')
    # 定義 CSV 檔案中的欄位名稱
    fields = ["編號", "資料長度", "來源MAC", "目的地MAC", "Eth類型", "時間戳記",
            "來源IP", "目的地IP", "來源端口", "目的地端口", "第三層協議", "第四層協議",
            "距離上一個封包的時間差(秒)", "1秒內取消驗證封包數", "1秒內Data封包數",
            "是否為Broadcast", "是否為重傳封包", "訊號強度差值", "是否為dos"]

    index = 0
    prev_packet_time = None
    broadcast_mac = 'ff:ff:ff:ff:ff:ff'
    packet_queue = deque()
    packet_dict = defaultdict(int)
    dos_threshold = 100  # 定義 DoS 閾值
    signal_strength_threshold = 10  # 定義信號強度閾值
    retransmission_threshold = 5  # 定義重傳封包閾值
    prev_signal_strength = None
    retransmission_dict = defaultdict(lambda: {'count': 0})
    data_packet_count = 0  # 初始化 data_packet_count 變量
    cancel_verification_count = 0


    # 創建並打開 CSV 檔案以進行寫入
    with open(output_csv, 'w', newline='',encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(fields)  # 寫入欄位名稱

        with open(input_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                index += 1  # 封包計數器遞增
                data_len = len(buf)  # 封包資料長度
                
                # 初始化來源端口和目的地端口為 None
                source_port = None
                dest_port = None

                eth = dpkt.ethernet.Ethernet(buf)  # 解析乙太網框架
                ip = eth.data if eth.type == dpkt.ethernet.ETH_TYPE_IP else None  # 提取IP封包

                # 如果不是IP封包，跳過
                if ip is None:
                    continue

                # 提取來源和目的地IP地址
                source_ip = socket.inet_ntoa(ip.src)
                dest_ip = socket.inet_ntoa(ip.dst)

                # 提取來源和目的地MAC地址，並轉換為人類可讀的格式
                source_mac = ':'.join(f'{b:02x}' for b in eth.src)
                dest_mac = ':'.join(f'{b:02x}' for b in eth.dst)
                eth_type = hex(eth.type)  # 乙太網類型轉換為十六進制格式

                # 計算距離上一個封包的時間差
                current_packet_time = datetime.fromtimestamp(timestamp)
                if prev_packet_time:
                    time_diff = (current_packet_time - prev_packet_time).total_seconds()
                else:
                    time_diff = 0
                prev_packet_time = current_packet_time

                # 檢查是否為Broadcast
                is_broadcast = source_mac == broadcast_mac or dest_mac == broadcast_mac

                # 提取訊號強度（假設訊號強度信息在IP封包的選項字段中）
                signal_strength = None
                if isinstance(ip, dpkt.ip.IP):
                    if ip.opts:
                        # 假設訊號強度信息存儲在IP選項字段的特定位置
                        signal_strength = int.from_bytes(ip.opts[:2], 'big')
                
                # 計算訊號強度差值
                if prev_signal_strength and signal_strength is not None:
                    signal_strength_diff = signal_strength - prev_signal_strength
                else:
                    signal_strength_diff = 0
                prev_signal_strength = signal_strength

                # 計算1秒內的取消驗證封包和Data封包數量
                while packet_queue and (timestamp - packet_queue[0][0]) > 1:
                    old_timestamp, old_packet_type = packet_queue.popleft()
                    if old_packet_type == 'cancel_verification':
                        cancel_verification_count -= 1
                    elif old_packet_type == 'data':
                        data_packet_count -= 1

                # 更新 IP 封包數量
                packet_dict[source_ip] += 1

                # 檢查封包是否為TCP或UDP
                if ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    trans = ip.data  # 傳輸層數據 (TCP/UDP)
                    source_port = trans.sport  # 來源端口
                    dest_port = trans.dport  # 目的地端口
                    layer3_protocol = ip.p  # 第三層協議 (IP協議號)
                    layer4_protocol = 'TCP' if ip.p == dpkt.ip.IP_PROTO_TCP else 'UDP'  # 第四層協議

                    # 檢查重傳封包邏輯
                    is_retransmission = False
                    if layer4_protocol == 'TCP':
                        if hasattr(trans, 'seq') and hasattr(trans, 'ack'):
                            # 假設重傳判斷依賴於序列號和確認號
                            retrans_key = (source_ip, source_port, dest_ip, dest_port)
                            if retrans_key not in retransmission_dict:
                                retransmission_dict[retrans_key] = (trans.seq, trans.ack)
                            else:
                                prev_seq, prev_ack = retransmission_dict[retrans_key]
                                if trans.seq == prev_seq and trans.ack == prev_ack:
                                    is_retransmission = True
                                    retransmission_dict[source_ip]['count'] += 1  # 增加重傳計數
                                retransmission_dict[retrans_key] = (trans.seq, trans.ack)

                    # 檢查取消驗證封包和
                    if layer4_protocol == 'TCP' and trans.flags & dpkt.tcp.TH_RST:
                        packet_type = 'cancel_verification'
                        cancel_verification_count += 1
                    else:
                        packet_type = 'data'
                        data_packet_count += 1
                    packet_queue.append((timestamp, packet_type))

                    # 檢查是否為dos攻擊
                    is_dos = (packet_dict[source_ip] > dos_threshold or 
                              abs(signal_strength_diff) > signal_strength_threshold or
                              retransmission_dict[source_ip]['count'] > retransmission_threshold)

                    # 將提取的數據寫入CSV檔案
                    writer.writerow([index, data_len, source_mac, dest_mac, eth_type,
                                     current_packet_time.strftime('%Y-%m-%d %H:%M:%S.%f'), source_ip, dest_ip, source_port,
                                     dest_port, layer3_protocol, layer4_protocol, time_diff, cancel_verification_count, 
                                     data_packet_count, "是" if is_broadcast else "否", is_retransmission, signal_strength_diff,
                                     "是" if is_dos else "否"])
                else:
                    # 如果封包不是TCP或UDP，則跳過
                    continue
            return output_csv
        
def read_csv_with_chardet(filepath):
    with open(filepath, 'rb') as f:
        result = chardet.detect(f.read())
    encoding = result['encoding']
    return pd.read_csv(filepath, encoding=encoding)

def predict_csv(filepath):
    try:
        df = read_csv_with_chardet(filepath)
    except UnicodeDecodeError:
        return render_template('index.html', error="無法讀取 CSV 文件，請確認文件編碼格式。")

    # 特徵選擇：選擇需要的特徵列
    features = ["距離上一個封包的時間差(秒)", "1秒內取消驗證封包數", "1秒內Data封包數", 
                "是否為Broadcast", "是否為重傳封包", "訊號強度差值"]
    
    X = df[features].copy()  
    y = df["是否為dos"]  

    # 將布林特徵轉換為數值
    X["是否為Broadcast"] = X["是否為Broadcast"].apply(lambda x: 1 if x == "是" else 0)
    X["是否為重傳封包"] = X["是否為重傳封包"].apply(lambda x: 1 if x else 0)

    # 標籤編碼
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y)

    # 切分數據為訓練集和測試集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # 標準化數據
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    # 訓練隨機森林分類器
    rf = RandomForestClassifier(n_estimators=10, random_state=42)
    rf.fit(X_train, y_train)

    # 訓練支持向量機分類器
    svm = SVC(kernel='linear', random_state=42)
    svm.fit(X_train, y_train)

    # 訓練K-近鄰分類器
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(X_train, y_train)

    # 比較準確率來確定最佳模型
    rf_accuracy = accuracy_score(y_test, rf.predict(X_test)) * 100
    svm_accuracy = accuracy_score(y_test, svm.predict(X_test)) * 100
    knn_accuracy = accuracy_score(y_test, knn.predict(X_test)) * 100

    # 確定最佳模型
    best_model_name = None
    best_model_score = max(rf_accuracy, svm_accuracy, knn_accuracy)

    if best_model_score == rf_accuracy:
        best_model_name = "隨機森林 (Random Forest)"
    elif best_model_score == svm_accuracy:
        best_model_name = "支持向量機 (Support Vector Machine)"
    else:
        best_model_name = "K-近鄰 (K-Nearest Neighbors)"

    # 將結果返回到模板中
    results = {
        "rf_accuracy": "{:.2f}%".format(rf_accuracy),
        "svm_accuracy": "{:.2f}%".format(svm_accuracy),
        "knn_accuracy": "{:.2f}%".format(knn_accuracy),
        "best_model_name": best_model_name,
    }

    return results


