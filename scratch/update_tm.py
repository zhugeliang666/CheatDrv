path_h = r'E:\Project\Drv\MainDrv\Transport\TransportManager.h'
with open(path_h, 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('#include "wsk_server.h"', '#include "wsk_server.h"\n#include "eth_server.h"')
text = text.replace('MK_SERVER_MODE_WSK_UDP = 3,', 'MK_SERVER_MODE_WSK_UDP = 3,\n    MK_SERVER_MODE_RAW_ETH = 4,')

with open(path_h, 'w', encoding='utf-8') as f:
    f.write(text)
print('TransportManager.h updated')
