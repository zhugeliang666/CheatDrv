import re, os

common_path = r'e:\Project\Drv\MainDrv\Core\Common.h'
core_path = r'e:\Project\Drv\MainDrv\Core\DriverCore.cpp'

with open(common_path, 'r', encoding='utf-8', errors='ignore') as fp:
    lines = fp.readlines()

fields = []
in_pfn = False
for line in lines:
    if 'typedef struct _MACHENIKE_PFN' in line:
        in_pfn = True
        continue
    if in_pfn and '} MACHENIKE_PFN;' in line:
        in_pfn = False
        break
    if in_pfn:
        clean = re.sub(r'//.*', '', line).strip()
        clean = re.sub(r'/\*.*?\*/', '', clean).strip()
        m = re.search(r'(\w+)\s*;', clean)
        if m:
            fields.append(m.group(1))

with open(core_path, 'r', encoding='utf-8', errors='ignore') as fp:
    lines = fp.readlines()

fa_items = []
in_fa = False
for line in lines:
    if 'ULONG FunctionArray[] = {' in line:
        in_fa = True
        continue
    if in_fa and '};' in line:
        in_fa = False
        break
    if in_fa:
        clean = re.sub(r'//.*', '', line).strip()
        clean = re.sub(r'/\*.*?\*/', '', clean).strip()
        for part in clean.split(','):
            part = part.strip()
            if part.startswith('str_'):
                fa_items.append(part[4:])

print(f'PFN fields count: {len(fields)}')
print(f'FunctionArray items count: {len(fa_items)}')

mismatch = False
for idx, (f, fa) in enumerate(zip(fields, fa_items)):
    if f != fa and not (f == 'pfnCSpecificHandler' and fa == '__C_specific_handler') and not (f == 'pfn_snprintf' and fa == '_snprintf') and not (f == 'pfn_vsnprintf' and fa == '_vsnprintf') and not (f == 'pPsInitialSystemProcess' and fa == 'PsInitialSystemProcess') and not (f == 'pPsThreadType' and fa == 'PsThreadType') and not (f == 'pIoDriverObjectType' and fa == 'IoDriverObjectType'):
        print(f'MISMATCH at [{idx}]: PFN field \"{f}\" != FunctionArray \"{fa}\"')
        mismatch = True

if not mismatch:
    print('SUCCESS! PFN and FunctionArray are 100% matched in order for first', min(len(fields), len(fa_items)), 'items!')

if len(fields) > len(fa_items):
    print('PFN has extra fields at end (resolved separately):', fields[len(fa_items):])
elif len(fa_items) > len(fields):
    print('FunctionArray has extra items at end:', fa_items[len(fields):])
