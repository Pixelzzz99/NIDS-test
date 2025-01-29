import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Ключи шифрования
KEY = b'1234567890123456'  # 16, 24 или 32 байта
IV = b'1234567890123456'   # 16 байт

# Серверные настройки
HOST = '127.0.0.1'
PORT = 9999

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Listening on {HOST}:{PORT}")

        while True:
            try:
                conn, addr = server.accept()
                print(f"Connected by {addr}")
                
                with conn:
                    encrypted_msg = conn.recv(1024)

                    # Проверяем, есть ли данные
                    if not encrypted_msg:
                        print("[Warning] Received empty message, closing connection.")
                        continue

                    try:
                        cipher = AES.new(KEY, AES.MODE_CBC, IV)
                        decrypted_msg = unpad(cipher.decrypt(encrypted_msg), AES.block_size)
                        print(f"[ALERT] Decrypted message: {decrypted_msg.decode('utf-8')}")
                    
                    except ValueError as e:
                        print(f"[Error] Failed to decrypt message: {e}")
                    
            except Exception as e:
                print(f"[Error] Connection error: {e}")
                continue

if __name__ == '__main__':
    start_server()
