import json

configs = [
    r"C:\Users\123\.gemini\antigravity\mcp_config.json",
    r"C:\Users\123\.gemini\antigravity-ide\mcp_config.json",
    r"C:\Users\123\.gemini\config\mcp_config.json"
]

for cfg in configs:
    try:
        with open(cfg, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if "mcpServers" in data and "windbg" in data["mcpServers"]:
            del data["mcpServers"]["windbg"]
            with open(cfg, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"Removed windbg from {cfg}")
        else:
            print(f"No windbg in {cfg}")
    except Exception as e:
        print(f"Error {cfg}: {e}")
