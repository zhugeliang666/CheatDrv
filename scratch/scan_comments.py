import os
import glob
import re

files = [
    p for p in glob.glob('vt/**/*', recursive=True)
    if os.path.isfile(p) and p.endswith(('.cpp', '.h', '.c', '.inl', '.asm'))
    and not any(x in p for x in ['business_backup', 'packages', 'bin', 'x64'])
]

total_comments = 0
for f in files:
    with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
        lines = fp.readlines()
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith(';') or stripped.startswith('*'):
            # check if mostly english
            words = re.findall(r'[a-zA-Z]{2,}', stripped)
            if len(words) >= 2:
                count += 1
    if count > 10:
        print(f"{f}: {count} comment lines")
        total_comments += count

print(f"Total: {total_comments}")
