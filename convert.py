import os
import json
import re
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

def clean_domain(domain):
    """強制清理域名開頭的 Clash/AdGuard 前綴 (+. 或 .)"""
    domain = domain.strip()
    while domain.startswith("+.") or domain.startswith("."):
        if domain.startswith("+."):
            domain = domain[2:]
        elif domain.startswith("."):
            domain = domain[1:]
    return domain

def parse_line(line, attr_tag=""):
    """清洗 Clash DOMAIN 語法，移除行內註解，處理解析通配符 * 與 ?"""
    line = line.strip()
    
    # 1. 忽略整行都是註解或 YAML 結構標頭
    if not line or line.startswith('#') or line.startswith('//') or line.startswith('payload:'):
        return None
    
    # 2. 先把行內註解 (# 或 // 後面的內容) 砍掉
    if ' #' in line:
        line = line.split(' #', 1)[0]
    elif '//' in line:
        line = line.split('//', 1)[0]
        
    line = line.strip()
    if not line:
        return None

    # 3. 清理 YAML / Clash 多餘符號 (減號、單雙引號)
    line = line.lstrip('- ').strip()
    line = line.replace("'", "").replace('"', '').strip()
    
    # 4. 判斷是否原本就有自訂 @ 屬性 (例如 line 裡面自帶 @gemini)
    attr_str = f" @{attr_tag}" if attr_tag else ""
    if " @" in line:
        line, inline_attr = line.split(" @", 1)
        attr_str = f" @{inline_attr.strip()}"

    rule_type = ""
    domain = line

    # 5. 處理逗號分隔的 Clash 格式 (例如 DOMAIN-SUFFIX,example.com)
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        rule_type = parts[0].upper()
        domain = parts[1]

    # 6. 強制清洗域名開頭 (+. 或 .)
    domain = clean_domain(domain)

    if not domain or domain.startswith('payload'):
        return None

    # 7. 如果域名裡面帶有 * 或 ? 通配符 (例如 awsdns-cn-??.biz 或 colab.*)
    if '*' in domain or '?' in domain:
        regex_domain = domain.replace('.', r'\.').replace('*', '.*').replace('?', '.')
        return f"regexp:^{regex_domain}${attr_str}"

    # 8. 輸出對應的 geosite 格式
    if rule_type in ['DOMAIN-SUFFIX', 'HOST-SUFFIX']:
        return f"{domain}{attr_str}"
    elif rule_type in ['DOMAIN', 'HOST']:
        return f"full:{domain}{attr_str}"
    elif rule_type in ['DOMAIN-KEYWORD', 'HOST-KEYWORD']:
        return f"keyword:{domain}{attr_str}"
    elif rule_type in ['REGEXP', 'URL-REGEX']:
        return f"regexp:{domain}{attr_str}"
    else:
        return f"{domain}{attr_str}"

# 開始處理每個 Tag
for tag, sources in config.items():
    rules_set = set()
    for src_item in sources:
        if isinstance(src_item, dict):
            src_url = src_item.get("url", "")
            attr_tag = src_item.get("attr", "")
        else:
            src_url = src_item
            attr_tag = ""

        lines = fetch_content(src_url)
        for line in lines:
            parsed = parse_line(line, attr_tag)
            if parsed:
                rules_set.add(parsed)
                
    out_path = f"data/{tag}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(rules_set))) + "\n")
        
    print(f"Tag [{tag}] 處理完成，共 {len(rules_set)} 條不重複域名。")

print("\n所有規則轉換完成！")
