import os
import re

# 锁定当前脚本运行的真实绝对路径，确保文件读取与生成都在同级目录下
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
REPORT_PATH = os.path.join(CURRENT_DIR, "scan-report.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 1. 提取账号私钥、公钥及内网 IP
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")

# 【核心微调】强制指定顶级抗封锁伪装 SNI
sni = "www.visa.cn"

# 2. 从扫描日志中提取可用节点
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
        
        # 匹配合法的 IPv4:端口 结构
        m = re.match(r'^\s*((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})\s+', line)
        if m:
            ep = m.group(1)
            if ep not in endpoints:
                endpoints.append(ep)

# 优选前 50 个高可用端点
endpoints = endpoints[:50]

if not endpoints:
    raise RuntimeError("未在 scan-report.txt 中找到可用端点！")

# 3. 组装支持国内分流与自动优选的 Mihomo 配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "# DNS 防污染与国内直连解析",
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

# 4. 策略组结构（主选择器 + 自动选优）
yaml_lines.extend([
    "proxy-groups:",
    "  # 主选择器：默认走自动选优，可在 Clash 客户端内随时展开单选指定节点",
    "  - name: 🚀 节点选择",
    "    type: select",
    "    proxies:",
    "      - ⚡ 自动优选",
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  # 自动选优组：后台定时向 Cloudflare trace 测速，自动切至最低延迟端点",
    "  - name: ⚡ 自动优选",
    "    type: url-test",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    ""
])

# 5. 国内精准分流规则
yaml_lines.extend([
    "rules:",
    "  # 局域网直连",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # 基础 NTP/DNS 端口直连",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  # 国内常见网站、应用与服务直连",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "",
    "  # 国内 IP 段直连",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 其余走 WARP",
    "  - MATCH,🚀 节点选择"
])

# 保存输出到同一目录下的 warp.yaml
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功生成配置: {OUTPUT_PATH}")
print(f"[OK] 已写入 {len(endpoints)} 个节点，强制伪装 SNI: {sni}")
