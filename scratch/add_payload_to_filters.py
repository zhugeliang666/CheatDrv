import re

filters_path = r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj.filters'
with open(filters_path, 'r', encoding='utf-8') as f:
    content = f.read()

target = '''    <ClInclude Include="common\\payload_abi.h">
      <Filter>Common</Filter>
    </ClInclude>'''

replacement = '''    <ClInclude Include="common\\payload_abi.h">
      <Filter>Common</Filter>
    </ClInclude>
    <ClInclude Include="common\\machenike_payload.h">
      <Filter>Common</Filter>
    </ClInclude>'''

assert target in content, "target not found"
content = content.replace(target, replacement, 1)

with open(filters_path, 'w', encoding='utf-8-sig', newline='\r\n') as f:
    f.write(content)

print("Updated filters successfully!")
