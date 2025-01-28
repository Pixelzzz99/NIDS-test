import socket
from Crypto.Cipher import AES 
from Crypto.Util.Padding import unpad

KEY = b'1234567890123456'
IV = b'1234567890123456'

HOST='127.0.0.1'
PORT=9999

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen(5)
        print('Listening on', (HOST, PORT))
        while True:
            conn, addr = server.accept()
            with conn:
                print('Connected by', addr)
                encrypted_msg = conn.recv(1024)
                cipher = AES.new(KEY, AES.MODE_CFB, IV)
                decrypted_msg = unpad(cipher.decrypt(encrypted_msg), AES.block_size)
                print(f"[ALERT] Decrypted message: {decrypted_msg.decode('utf-8')}")


if __name__ == '__main__':
    start_server()
