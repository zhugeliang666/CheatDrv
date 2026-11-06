# 更新 Machenike.vcxproj
proj_path = r'E:\Project\Drv\MainDrv\Machenike.vcxproj'
with open(proj_path, 'r', encoding='utf-8') as f:
    text = f.read()

if 'Transport\\eth_server.c' not in text:
    text = text.replace(
        '<ClCompile Include="Transport\\udp_server.c" />',
        '<ClCompile Include="Transport\\udp_server.c" />\n    <ClCompile Include="Transport\\eth_server.c" />'
    )
if 'Transport\\eth_server.h' not in text:
    text = text.replace(
        '<ClInclude Include="Transport\\udp_server.h" />',
        '<ClInclude Include="Transport\\udp_server.h" />\n    <ClInclude Include="Transport\\eth_server.h" />'
    )

with open(proj_path, 'w', encoding='utf-8') as f:
    f.write(text)

# 更新 Machenike.vcxproj.filters
filters_path = r'E:\Project\Drv\MainDrv\Machenike.vcxproj.filters'
with open(filters_path, 'r', encoding='utf-8') as f:
    f_text = f.read()

if 'Transport\\eth_server.c' not in f_text:
    f_text = f_text.replace(
        '<ClCompile Include="Transport\\udp_server.c">\n      <Filter>Transport</Filter>\n    </ClCompile>',
        '<ClCompile Include="Transport\\udp_server.c">\n      <Filter>Transport</Filter>\n    </ClCompile>\n    <ClCompile Include="Transport\\eth_server.c">\n      <Filter>Transport</Filter>\n    </ClCompile>'
    )
if 'Transport\\eth_server.h' not in f_text:
    f_text = f_text.replace(
        '<ClInclude Include="Transport\\udp_server.h">\n      <Filter>Transport</Filter>\n    </ClInclude>',
        '<ClInclude Include="Transport\\udp_server.h">\n      <Filter>Transport</Filter>\n    </ClInclude>\n    <ClInclude Include="Transport\\eth_server.h">\n      <Filter>Transport</Filter>\n    </ClInclude>'
    )

with open(filters_path, 'w', encoding='utf-8') as f:
    f.write(f_text)

print('Updated project and filters files!')
