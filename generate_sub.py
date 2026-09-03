import os
import re
from collections import defaultdict

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
REPORT_PATH = os.path.join(CURRENT_DIR, "scan-report.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 1. 顶级异构伪装 SNI
SNI_POOL = [
    "www.visa.cn",
    "www.mastercard.com.cn",
    "www.apple.com",
    "www.tesla.cn"
]

# 2. 提取 MASQUE 账号凭据（供外层抗审查用）
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

masque_priv = get_val("private-key")
masque_pub = get_val("public-key")
masque_ip = get_val("ip")
masque_ipv6 = get_val("ipv6")

# 3. 提取标准 WireGuard 凭据（供内层隧道洗白地区用）
# Cloudflare WARP 固定的公共端点公钥
WG_PEER_PUB = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
# 内层固定 WireGuard 接入端点（Cloudflare 知名内网路由地址）
INNER_WG_ENDPOINT = "162.159.192.1"
INNER_WG_PORT = 2408

# 4. 从报告中提取可用端点并按端口离散化
port_buckets = defaultdict(list)
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
        
        m = re.match(r'^\s*((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\s+', line)
        if m:
            host, port = m.group(1), m.group(2)
            ep = f"{host}:{port}"
            if ep not in port_buckets[port]:
                port_buckets[port].append(ep)

# 挑选 20 个高质量外层承载端点（做链式代理 20 个足够充沛且测速不卡顿）
balanced_endpoints = []
preferred_ports = ["443", "8443", "1701", "4443", "8095", "500", "4500"]
for p in port_buckets.keys():
    if p not in preferred_ports:
        preferred_ports.append(p)

while len(balanced_endpoints) < 20:
    added = False
    for p in preferred_ports:
        if port_buckets[p]:
            balanced_endpoints.append(port_buckets[p].pop(0))
            added = True
            if len(balanced_endpoints) >= 20:
                break
    if not added:
        break

if not balanced_endpoints:
    raise RuntimeError("未能从扫描日志提取到有效端点！")

# 5. 构造 Mihomo 配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
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
    "",
    "proxies:"
]

chain_node_names = []

# 核心：循环生成 [外层承载 MASQUE] + [内层链式 WireGuard]
for idx, ep in enumerate(balanced_endpoints, 1):
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    
    outer_name = f"OUTER-{idx:02d}-{port}"
    inner_name = f"🔗WARP-Chain-{idx:02d}"
    chain_node_names.append(inner_name)

    # 1. 外层代理 (MASQUE-H2)
    yaml_lines.extend([
        f"  - name: '{outer_name}'",
        "    type: masque",
        f"    server: '{host}'",
        f"    port: {port}",
        "    network: h2",
        f"    sni: '{assigned_sni}'",
        f"    private-key: '{masque_priv}'",
        f"    public-key: '{masque_pub}'",
        f"    ip: '{masque_ip}'",
    ])
    if masque_ipv6:
        yaml_lines.append(f"    ipv6: '{masque_ipv6}'")
    yaml_lines.extend([
        "    udp: true",
        "    remote-dns-resolve: true",
        "    dns: [1.1.1.1, 1.0.0.1]",
        ""
    ])

    # 2. 内层代理 (WireGuard，通过 dialer-proxy 挂载在外层上，洗去 CN 区域标签)
    yaml_lines.extend([
        f"  - name: '{inner_name}'",
        "    type: wireguard",
        f"    server: '{INNER_WG_ENDPOINT}'",
        f"    port: {INNER_WG_PORT}",
        "    ip: '172.16.0.3'", # 规避冲突的内网地址
        f"    public-key: '{WG_PEER_PUB}'",
        f"    private-key: '{masque_priv}'",
        "    udp: true",
        "    remote-dns-resolve: true",
        "    dns: [1.1.1.1, 1.0.0.1]",
        f"    dialer-proxy: '{outer_name}'", # 关键：建立双层链式链路
        ""
    ])

# 6. 策略组结构配置
yaml_lines.extend([
    "proxy-groups:",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
    "      - 🛡️ 故障转移",
    "      - DIRECT",
] + [f"      - '{name}'" for name in chain_node_names] + [
    "",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
    "      - 🛡️ 故障转移",  # 优先走 IP 固定的 fallback 组
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
] + [f"      - '{name}'" for name in chain_node_names] + [
    "",
    "  - name: 🛡️ 故障转移",
    "    type: fallback",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in chain_node_names] + [
    ""
])

# 7. 全场景高精分流规则
yaml_lines.extend([
    "rules:",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # P2P/BT 强制直连",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Transmission.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - PROCESS-NAME,BitComet.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  # 广告拦截",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "",
    "  # AI 服务专属规则 (包括 Google Gemini 域名)",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "  - DOMAIN-KEYWORD,gemini,🤖 人工智能",
    "  - DOMAIN-SUFFIX,bard.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,generativeai.google,🤖 人工智能",
    "",
    "  # 境外多媒体",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "",
    "  # 大陆直连白名单",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功生成链式代理配置: {OUTPUT_PATH}")
print(f"[OK] 已构建 {len(chain_node_names)} 组 WARP-in-WARP 双层跳板！")
