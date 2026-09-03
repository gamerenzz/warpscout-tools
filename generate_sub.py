import os
import re
from collections import defaultdict

# 锁定脚本执行绝对路径，确保文件读取与输出严格在同级目录
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
REPORT_PATH = os.path.join(CURRENT_DIR, "scan-report.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 1. 异构顶级白名单 SNI 伪装池（金融机构、跨国车企与顶级科技厂商）
SNI_POOL = [
    "www.visa.cn",
    "www.mastercard.com.cn",
    "www.apple.com",
    "www.tesla.cn"
]

# 2. 读取凭据
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")

# 3. 从报告中提取可用端点并按端口分类
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
            host = m.group(1)
            port = m.group(2)
            ep = f"{host}:{port}"
            if ep not in port_buckets[port]:
                port_buckets[port].append(ep)

# 4. 端口离散轮询（确保 443, 8443, 1701 等各端口均衡交错分布）
balanced_endpoints = []
# 优先选用的主流端口顺序
preferred_ports = ["443", "8443", "1701", "4443", "8095", "500", "4500"]
# 将其他扫描出的端口追加到后方
for p in port_buckets.keys():
    if p not in preferred_ports:
        preferred_ports.append(p)

while len(balanced_endpoints) < 40:
    added_in_round = False
    for p in preferred_ports:
        if port_buckets[p]:
            balanced_endpoints.append(port_buckets[p].pop(0))
            added_in_round = True
            if len(balanced_endpoints) >= 40:
                break
    if not added_in_round:
        break

if not balanced_endpoints:
    raise RuntimeError("未能从扫描报告中提取到任何有效节点！")

# 5. 构建 Mihomo 完整结构
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
    "    - 8.8.8.8",
    "",
    "proxies:"
]

node_names = []
for idx, ep in enumerate(balanced_endpoints, 1):
    host, port = ep.split(":")
    # 轮询选用不同 SNI，分散审查风险
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    name = f"WARP-H2-{idx:02d}-{port}"
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

# 6. 精细化策略组架构
yaml_lines.extend([
    "proxy-groups:",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
    "      - DIRECT",
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
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
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    ""
])

# 7. 全场景高精分流规则
yaml_lines.extend([
    "rules:",
    "  # 1. 私有网段 & 本地局域网直连",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # 2. 严防 BT / P2P 下载走 WARP（防止封号及异常限速）",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Transmission.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - PROCESS-NAME,BitComet.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "",
    "  # 3. 常见基础服务与 NTP 端口放行",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  # 4. 全局广告拦截",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "",
    "  # 5. AI 服务走专属分流组",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "",
    "  # 6. 常见境外主流多媒体",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "",
    "  # 7. 大陆全域直连白名单",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 8. 兜底规则走默认代理组",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功生成配置: {OUTPUT_PATH}")
print(f"[OK] 已混编重组 {len(balanced_endpoints)} 个节点！")
print(f"[OK] 已应用 {len(SNI_POOL)} 组顶级异构伪装 SNI 及高精分流策略！")
