import os
import sys

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def convert_and_fix_newlines(filepath):
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()

        content = None
        for encoding in ['utf-8-sig', 'gbk', 'utf-8', 'utf-16']:
            try:
                content = raw.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if content is None:
            print(f'解码失败 {filepath}，跳过')
            return

        content = content.lstrip('\ufeff')
        normalized_content = content.replace('\r\n', '\n').replace('\r', '\n')
        crlf_content = normalized_content.replace('\n', '\r\n')
        output_bytes = crlf_content.encode('utf-8-sig')

        if raw != output_bytes:
            with open(filepath, 'wb') as f:
                f.write(output_bytes)
            print(f'已转换编码并修正换行符 (UTF-8 BOM + CRLF): {filepath}')

    except Exception as e:
        print(f'处理失败 {filepath}: {e}')

def process_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.cpp', '.h', '.hpp', '.c')):
                filepath = os.path.join(root, file)
                convert_and_fix_newlines(filepath)

if __name__ == '__main__':
    target_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    print(f'开始扫描并转换目录: {os.path.abspath(target_dir)}')
    process_directory(target_dir)
    print('转换与规范化完成')