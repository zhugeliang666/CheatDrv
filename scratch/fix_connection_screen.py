import re

path = r'E:\Project\Drv\CheatFrameWork\LeechFrameWork\front_loader_ui\frontend\shared\components\ConnectionScreen.tsx'

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. 恢复 import { WindowMinimise, Quit }
if "WindowMinimise, Quit" not in content and "Quit, WindowMinimise" not in content:
    target = "import { ConnectMode } from '../constants/connection';"
    replacement = "import { ConnectMode } from '../constants/connection';\nimport { WindowMinimise, Quit } from '../../wailsjs/runtime/runtime';"
    if target in content:
        content = content.replace(target, replacement, 1)
        print("Import added successfully")
    else:
        print("Target for import not found")

# 2. 拓扑图与优势判断：由 selectedModeId === 'leech' 扩展为 (selectedModeId === 'tcp' || selectedModeId === 'leech')
count = content.count("{selectedModeId === 'leech' && (")
print(f"Found {count} occurrences of {{selectedModeId === 'leech' && (}}")
content = content.replace("{selectedModeId === 'leech' && (", "{(selectedModeId === 'tcp' || selectedModeId === 'leech') && (")

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    f.write(content)

print("File updated successfully")
