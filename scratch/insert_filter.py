with open(r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj.filters', 'r', encoding='utf-8') as f:
    text = f.read()

lines = text.splitlines(keepends=True)
new_lines = []
inserted = False
for l in lines:
    new_lines.append(l)
    if not inserted and '</ClInclude>' in l and len(new_lines) >= 3 and 'resident_payload.h' in new_lines[-3]:
        eol = '\r\n' if l.endswith('\r\n') else '\n'
        new_lines.append('    <ClInclude Include="common\\machenike_payload.h">' + eol)
        new_lines.append('      <Filter>Common</Filter>' + eol)
        new_lines.append('    </ClInclude>' + eol)
        inserted = True

assert inserted, "failed to insert"
with open(r'vt\VtBootstrapDriver\VtBootstrapDriver.vcxproj.filters', 'w', encoding='utf-8-sig', newline='') as f:
    f.writelines(new_lines)
print('SUCCESS!')
