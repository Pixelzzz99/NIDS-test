import socket
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import sniff, IP, TCP

# Шифрование
KEY = b'1234567890123456'  # Должно быть 16, 24 или 32 байта
IV = b'1234567890123456'   # Должно быть 16 байт

# Настройки сервера
HOST = '127.0.0.1'
PORT = 9999

# Статистика сетевого трафика
traffic_stats = {
    "total_packets": 0,
    "sources": {},
    "port_scans": {},
    "dos_attacks": {}
}

DOS_TIME_WINDOW = 5  # Время окна в секундах
DOS_PACKET_THRESHOLD = 1000  # Максимальное число пакетов за 5 сек

# Пороговые значения
PORT_SCAN_THRESHOLD = 5  # Порог для порт-сканирования

def send_alert_to_server(alert_message):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        encrypted_message = cipher.encrypt(pad(alert_message.encode('utf-8'), AES.block_size))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((HOST, PORT))  # Исправлено!
            client.sendall(encrypted_message)
            time.sleep(1)  # Даем серверу время обработать сообщение
            print(f"Alert sent to server: {alert_message}")

    except Exception as e:
        print(f"[Error] Failed to send alert: {e}")

def detect_dos(src_ip):
    current_time = time.time()

    # Если у IP нет записей, создаем
    if src_ip not in traffic_stats["dos_attacks"]:
        traffic_stats["dos_attacks"][src_ip] = []

    # Добавляем текущий пакет в историю
    traffic_stats["dos_attacks"][src_ip].append(current_time)

    # Удаляем старые записи (старше 5 секунд)
    traffic_stats["dos_attacks"][src_ip] = [
        t for t in traffic_stats["dos_attacks"][src_ip] if current_time - t <= DOS_TIME_WINDOW
    ]

    # Проверяем, превысило ли количество пакетов порог
    if len(traffic_stats["dos_attacks"][src_ip]) > DOS_PACKET_THRESHOLD:
        alert = f"[ALERT] Possible DoS attack from {src_ip}, {len(traffic_stats['dos_attacks'][src_ip])} packets in {DOS_TIME_WINDOW} seconds"
        print(alert)
        send_alert_to_server(alert)

def track_port_scan(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if src_ip not in traffic_stats['port_scans']:
            traffic_stats['port_scans'][src_ip] = set()
        traffic_stats['port_scans'][src_ip].add(dst_port)

        unique_ports = len(traffic_stats['port_scans'][src_ip])
        if unique_ports > PORT_SCAN_THRESHOLD:
            alert = f'[ALERT] Port scan detected from {src_ip}, unique ports: {unique_ports}'
            send_alert_to_server(alert)

# Обработчик пакетов
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Обновляем статистику источников
        if src_ip in traffic_stats["sources"]:
            traffic_stats["sources"][src_ip] += 1
        else:
            traffic_stats["sources"][src_ip] = 1

        # Проверяем на DoS-атаку
        detect_dos(src_ip)

    # Проверяем на порт-сканирование
    track_port_scan(packet)

# Запускаем NIDS
print("Starting packet sniffing...")
sniff(prn=packet_callback)  # Бесконечный захват пакетов



