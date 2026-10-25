import json

configs = [
    r"C:\Users\123\.gemini\antigravity\mcp_config.json",
    r"C:\Users\123\.gemini\antigravity-ide\mcp_config.json",
    r"C:\Users\123\.gemini\config\mcp_config.json"
]

windbg_entry = {
    "command": "uvx",
    "args": [
        "mcp-windbg",
        "--cdb-path",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        "--kd-path",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
        "--symbols-path",
        r"SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"
    ],
    "env": {
        "_NT_SYMBOL_PATH": r"SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"
    }
}

for cfg in configs:
    try:
        with open(cfg, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if "mcpServers" not in data:
            data["mcpServers"] = {}
        data["mcpServers"]["windbg"] = windbg_entry
        with open(cfg, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"Added windbg to {cfg}")
    except Exception as e:
        print(f"Error {cfg}: {e}")
