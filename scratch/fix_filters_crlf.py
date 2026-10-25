import os
import xml.etree.ElementTree as ET

def clean_file(fpath):
    with open(fpath, 'rb') as f:
        data = f.read()
    
    # Remove BOM if present
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    
    # Replace all \r\r\n or \r\n with \n
    text = data.decode('utf-8')
    text = text.replace('\r\r\n', '\n').replace('\r\n', '\n').replace('\r', '\n')
    
    # Convert back to standard CRLF with UTF-8 BOM
    lines = [l for l in text.split('\n')]
    # Remove excessive blank lines if any
    clean_lines = []
    for l in lines:
        if l.strip() == '' and clean_lines and clean_lines[-1].strip() == '':
            continue
        clean_lines.append(l)
    
    result = '\r\n'.join(clean_lines).strip() + '\r\n'
    with open(fpath, 'wb') as f:
        f.write(b'\xef\xbb\xbf' + result.encode('utf-8'))
    print(f"Cleaned {fpath}")

# 1. First add common\machenike_payload.h into VtBootstrapDriver.vcxproj.filters if missing
b_filters = r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj.filters'
with open(b_filters, 'r', encoding='utf-8', errors='ignore') as f:
    text = f.read()

text = text.replace('\r\r\n', '\n').replace('\r\n', '\n')
if 'machenike_payload.h' not in text:
    target = '<ClInclude Include="common\\resident_payload.h">\n      <Filter>Common</Filter>\n    </ClInclude>'
    replacement = target + '\n    <ClInclude Include="common\\machenike_payload.h">\n      <Filter>Common</Filter>\n    </ClInclude>'
    if target in text:
        text = text.replace(target, replacement)
        print("Added machenike_payload.h into VtBootstrapDriver.vcxproj.filters")
    else:
        print("Target pattern resident_payload.h not found directly, adding to ClInclude group")
        text = text.replace('</ItemGroup>', '    <ClInclude Include="common\\machenike_payload.h">\n      <Filter>Common</Filter>\n    </ClInclude>\n  </ItemGroup>', 2)

with open(b_filters, 'w', encoding='utf-8') as f:
    f.write(text)

# 2. Clean all filters files
clean_file(r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj.filters')
clean_file(r'vt\VtHypervisor\VtHypervisor.vcxproj.filters')
clean_file(r'vt\VtResidentPayload\VtResidentPayload.vcxproj.filters')

# 3. Touch all .vcxproj files with a timestamp comment so VS detects change and prompts reload
import time
ts = time.strftime("%Y-%m-%d %H:%M:%S")

for vcx in [r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj', r'vt\VtHypervisor\VtHypervisor.vcxproj', r'vt\VtResidentPayload\VtResidentPayload.vcxproj']:
    clean_file(vcx)
    with open(vcx, 'rb') as f:
        data = f.read()
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    text = data.decode('utf-8')
    text = text.replace('\r\r\n', '\n').replace('\r\n', '\n')
    
    # Update or add reload trigger comment
    import re
    text = re.sub(r'<!-- Reload Trigger: .*? -->\n?', '', text)
    text = text.rstrip() + f'\n<!-- Reload Trigger: {ts} -->\n'
    
    result = text.replace('\n', '\r\n')
    with open(vcx, 'wb') as f:
        f.write(b'\xef\xbb\xbf' + result.encode('utf-8'))
    print(f"Updated reload trigger in {vcx}")

print("All done!")
