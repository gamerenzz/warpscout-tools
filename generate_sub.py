import os
import re

# 获取当前脚本所在的绝对目录，确保生成的 yaml 就在同级目录下
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
REPORT_PATH = os.path.join(CURRENT_DIR, "scan-report.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

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
sni = get_val("sni")

# 2. 提取可用端点
endpoints = []
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
        
        m = re.match(r'^\s*([\d\.]+:\d+)\s+', line)
        if m:
            ep = m.group(1)
            if ep not in endpoints:
                endpoints.append(ep)

# 限制前 50 个优质节点
endpoints = endpoints[:50]

# 3. 构造 Mihomo (Clash Meta) 完整增强配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "# DNS 模块配置，防止 DNS 污染并保证国内域名直连解析",
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
for idx, ep in enumerate(endpoints, 1):
    name = f"WARP-H2-{idx:02d}"
    node_names.append(name)
    host, port = ep.split(":")
    yaml_lines.extend([
        f"  - name: '{name}'",
        "    type: masque",
        f"    server: '{host}'",
        f"    port: {port}",
        "    network: h2",
        f"    sni: '{sni}'",
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

# 4. 增强策略组：主选择器 + 自动选优
yaml_lines.extend([
    "proxy-groups:",
    "  # 主策略组：默认开启自动选优，也可以展开手动指定具体节点",
    "  - name: 🚀 节点选择",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  # 自动优选策略组：后台测速并无感切换到最低延迟",
    "  - name: ⚡ 自动优选",
    "    type: url-test",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    ""
])

# 5. 国内分流规则（国内域名、IP直连；其余走代理）
yaml_lines.extend([
    "rules:",
    "  # 局域网与本机流量直接放行",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # 常见国内 DNS / NTP 等服务直连",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  # 国内常用域名及主流平台直连 (利用 Mihomo 内置规则集合)",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "",
    "  # 国内 IP 段直连",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 其余全部走 WARP 节点选择器",
    "  - MATCH,🚀 节点选择"
])

# 写入当前目录
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功生成文件: {OUTPUT_PATH}")
print(f"[OK] 共包含 {len(endpoints)} 个节点并已配置国内直连分流！")
