path_cpp = r'E:\Project\Drv\MainDrv\Transport\TransportManager.cpp'
with open(path_cpp, 'r', encoding='utf-8') as f:
    lines = f.readlines()

for idx, l in enumerate(lines):
    if any(k in l for k in ['StopServerLocked', 'StartServer', 'GetStatus', 'IsUsbMode']):
        print(f"L{idx+1}: {l.strip()}")
