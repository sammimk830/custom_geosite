import os
import json
import urllib.request

# 建立 output 資料夾
os.makedirs("data", exist_ok=True)

with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

def fetch_content(source):
    """判斷是網址還是本地檔案，並讀取內容"""
    if source.startswith("http://") or source.startswith("https://"):
        print(f"正在下載遠端規則: {source}")
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req) as response:
                return response.read().decode('utf-8').splitlines()
        except Exception as e:
            print(f"下載失敗 {source}: {e}")
            return []
    else:
        print(f"正在讀取本地規則: {source}")
        if os.path.exists(source):
            with open(source, "r", encoding="utf-8") as f:
                return f.readlines()
        else:
            print(f"警告：找不到本地檔案 {source}")
            return []

def parse_line(line):
    """清洗 Clash DOMAIN 語法，轉成 geosite 格式"""
    line = line.strip()
    if not line or line.startswith(('#', '//', 'payload:')):
        return None
    
    # 去除 YAML 符號與多餘空白
    line = line.replace("'", "").replace('"', '').lstrip('- ').strip()
    
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        rule_type = parts[0].upper()
        domain = parts[1]
        
        if rule_type in ['DOMAIN-SUFFIX', 'HOST-SUFFIX']:
            return domain                       # geosite 預設 domain 包含子網域
        elif rule_type in ['DOMAIN', 'HOST']:
            return f"full:{domain}"             # 完全匹配
        elif rule_type in ['DOMAIN-KEYWORD', 'HOST-KEYWORD']:
            return f"keyword:{domain}"          # 關鍵字
        elif rule_type in ['REGEXP', 'URL-REGEX']:
            return f"regexp:{domain}"           # 正則
    else:
        if not line.startswith('payload'):
            return line
            
    return None

# 開始處理每個 Tag
for tag, sources in config.items():
    rules_set = set()  # 使用 set 自動去重
    for src in sources:
        lines = fetch_content(src)
        for line in lines:
            parsed = parse_line(line)
            if parsed:
                rules_set.add(parsed)
                
    out_path = f"data/{tag}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(rules_set))) + "\n")
        
    print(f"Tag [{tag}] 處理完成，共 {len(rules_set)} 條不重複域名。")

print("所有規則轉換完成！")
