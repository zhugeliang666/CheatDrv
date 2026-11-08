import os
import sys

def convert_and_fix_newlines(filepath):
    try:
        # 1. 以二进制读取文件原始内容
        with open(filepath, 'rb') as f:
            raw = f.read()

        # 2. 尝试使用常见编码进行安全解码
        content = None
        for encoding in ['utf-8-sig', 'gbk', 'utf-8', 'utf-16']:
            try:
                content = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            print(f"解码失败 {filepath}，跳过。")
            return

        # 3. 规范化换行符：先统一转换为空白 \n
        normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')
        
        # 4. 统一转换为标准的 CRLF (\r\n)
        crlf_content = normalized_content.replace('\n', '\r\n')

        # 5. 将字符串以 utf-8-sig (即带 BOM 的 UTF-8) 重新编码为字节流
        # utf-8-sig 会在头部自动添加 \xef\xbb\xbf 字节
        output_bytes = crlf_content.encode('utf-8-sig')

        # 6. 使用二进制写入 'wb'，避免 Python 文本模式对换行符的二次处理，从根源防止 \r\r\n 问题
        if raw != output_bytes:
            with open(filepath, 'wb') as f:
                f.write(output_bytes)
            print(f"已转换编码并修正换行符 (UTF-8 BOM + CRLF): {filepath}")

    except Exception as e:
        print(f"处理失败 {filepath}: {e}")

def process_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.cpp', '.h', '.hpp', '.c')):
                filepath = os.path.join(root, file)
                convert_and_fix_newlines(filepath)

if __name__ == '__main__':
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(f"开始扫描并转换目录: {os.path.abspath(target_dir)}")
    process_directory(target_dir)
    print("转换与规范化完成！")
