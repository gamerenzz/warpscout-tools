import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
REPORT_PATH = os.path.join(CURRENT_DIR, "scan-report.txt")
TXT_PATH = os.path.join(CURRENT_DIR, "endpoints.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

SNI_POOL = [
    "www.apple.com",
    "www.visa.cn",
    "www.tesla.cn",
    "www.mastercard.com.cn"
]

# 1. 提取凭据
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")

# 2. 端点获取策略：优先读取本地优选的 endpoints.txt
target_endpoints = []

if os.path.exists(TXT_PATH):
    print(f"[INFO] 发现本地优选端点文件: {TXT_PATH}，优先载入...")
    with open(TXT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # 过滤注释和空行，严格匹配 IP:Port
            if line and not line.startswith("#"):
                m = re.match(r'^((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})', line)
                if m and m.group(1) not in target_endpoints:
                    target_endpoints.append(m.group(1))

# 如果没有 endpoints.txt 或为空，才从扫描报告中抓取
if not target_endpoints and os.path.exists(REPORT_PATH):
    print("[INFO] 未找到有效 txt 端点，回退至从 scan-report.txt 动态提取...")
    working = []
    seen = set()
    in_table = False
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("ENDPOINT"):
                in_table = True
                continue
            if "#" in line and "torn down" in line:
                break
            if not in_table:
                continue
            m = re.match(r'^\s*((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\s+(\d+(?:\.\d+)?ms|\?)\s+', line)
            if m:
                ep, ping_str = m.group(1), m.group(2)
                if ep not in seen:
                    seen.add(ep)
                    ping_val = float(ping_str.replace("ms", "")) if ping_str != "?" else 999999.0
                    working.append({"endpoint": ep, "ping": ping_val})
    working.sort(key=lambda x: x["ping"])
    target_endpoints = [x["endpoint"] for x in working[:30]]

if not target_endpoints:
    raise RuntimeError("未能提取到任何有效节点，请检查配置文件！")

target_endpoints = target_endpoints[:30]

# 3. 构造 Mihomo 配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "tcp-concurrent: true",
    "global-client-fingerprint: chrome",
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "  fallback:",
    "    - 1.1.1.1",
    "    - 8.8.8.8",
    "",
    "proxies:"
]

node_names = []
for idx, ep in enumerate(target_endpoints, 1):
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    name = f"WARP-极速-{idx:02d}-{port}"
    node_names.append(name)

    yaml_lines.extend([
        f"  - name: '{name}'",
        "    type: masque",
        f"    server: '{host}'",
        f"    port: {port}",
        "    network: h2",
        f"    sni: '{assigned_sni}'",
        f"    private-key: '{private_key}'",
        f"    public-key: '{public_key}'",
        f"    ip: '{ip}'",
    ])
    if ipv6:
        yaml_lines.append(f"    ipv6: '{ipv6}'")
    yaml_lines.extend([
        "    udp: true",
        "    remote-dns-resolve: true",
        "    dns: [1.1.1.1, 1.0.0.1]",
        ""
    ])

yaml_lines.extend([
    "proxy-groups:",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
    "      - 🛡️ 故障转移",
    "      - DIRECT",
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
    "      - 🛡️ 故障转移",
    "      - ⚡ 自动优选",
    "      - 🚀 默认代理",
    "",
    "  - name: 📺 国际媒体",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
    "      - 🚀 默认代理",
    "",
    "  - name: 🛑 广告拦截",
    "    type: select",
    "    proxies:",
    "      - REJECT",
    "      - DIRECT",
    "",
    "  - name: ⚡ 自动优选",
    "    type: url-test",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  - name: 🛡️ 故障转移",
    "    type: fallback",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "rules:",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Transmission.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - PROCESS-NAME,BitComet.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功生成配置！共写入 {len(target_endpoints)} 个节点至: {OUTPUT_PATH}")
