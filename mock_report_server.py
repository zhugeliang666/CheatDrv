# ============================================================
# mock_report_server.py — CheatDrv 内核驱动异常上报本地接收与解密验证服务
# ============================================================
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import struct

REPORT_SECRET_KEY = bytes([0x13, 0x5D, 0x03, 0x09, 0x5D, 0x27, 0x43, 0x44, 0x5D])

def decrypt_report_payload(enc_hex_str: str) -> str:
    """
    解密驱动 Main_EncryptReportData 导出的 Hex 载荷
    结构: A(4B) + B(4B) + CipherPayload(N Bytes)
    """
    try:
        bin_data = bytes.fromhex(enc_hex_str)
        if len(bin_data) < 8:
            return ""
        
        a_val = struct.unpack("<I", bin_data[0:4])[0]
        b_val = struct.unpack("<I", bin_data[4:8])[0]
        and_val = (~(a_val ^ b_val)) & 0xFF
        
        key_time = list(bin_data[4:8])
        time_key = [(k ^ and_val) & 0xFF for k in key_time]
        
        key_copy = list(REPORT_SECRET_KEY)
        final_key_xor = 0
        current_idx = 0
        
        for i in range(9):
            if current_idx >= 4:
                current_idx = 0
            key_copy[i] ^= time_key[current_idx]
            final_key_xor ^= key_copy[i]
            current_idx += 1
            
        cipher_bytes = bin_data[8:]
        plain_hex_bytes = bytearray()
        
        for b in cipher_bytes:
            if current_idx >= 4:
                current_idx = 0
            p = b ^ time_key[current_idx] ^ final_key_xor
            plain_hex_bytes.append(p)
            current_idx += 1
            
        plain_hex_str = plain_hex_bytes.decode('ascii', errors='ignore')
        plain_bytes = bytes.fromhex(plain_hex_str)
        return plain_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[解密异常: {e}]"

class ReportHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        print("\n" + "=" * 65)
        print(f"[*] 收到内核驱动 WSK 异常上报请求! 来自: {self.client_address}")
        print(f"[*] 请求路径: {self.path}")
        print(f"[*] 客户端 User-Agent: {self.headers.get('User-Agent')}")
        print("-" * 65)
        
        params = parse_qs(body)
        func_name = params.get('functionName', ['<None>'])[0]
        status_code = params.get('status', ['<None>'])[0]
        h_payload = params.get('h', [''])[0]
        message = params.get('message', [''])[0]
        
        print(f"[+] 上报函数: {func_name}")
        print(f"[+] 异常状态: {status_code}")
        
        if message:
            print(f"[+] 明文消息: {message}")
            
        if h_payload:
            print(f"[+] 密文载荷(h): {h_payload[:40]}... (共 {len(h_payload)} 字符)")
            decrypted = decrypt_report_payload(h_payload)
            print("-" * 65)
            print("[+] 密文解密还原数据:")
            print(decrypted)
            
        print("=" * 65 + "\n")
        
        # 响应 200 OK 结束会话
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK")
        
    def log_message(self, format, *args):
        # 抑制默认控制台日志以保证输出清晰
        pass

def run(port=8888):
    server_addr = ('0.0.0.0', port)
    httpd = HTTPServer(server_addr, ReportHandler)
    print("=" * 65)
    print(f" [*] CheatDrv 驱动异常上报本地 Mock 服务已就绪!")
    print(f" [*] 监听端口: {port}")
    print(f" [*] 上报端点: http://127.0.0.1:{port}/api/tg")
    print(f" [*] 等待驱动发送 POST 请求 (按 Ctrl+C 可停止服务)...")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务已停止。")

if __name__ == '__main__':
    port = 8888
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run(port)
