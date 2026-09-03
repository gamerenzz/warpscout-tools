import re
import json

# 1. 从 best-mihomo.yaml 中提取凭据
with open("best-mihomo.yaml", "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")
sni = get_val("sni")

# 2. 从 scan-report.txt 中抓取所有可用的 endpoint
endpoints = []
in_table = False

with open("scan-report.txt", "r", encoding="utf-8") as f:
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

# 限制节点数量，例如最多放 30~50 个节点供本地测速竞争
endpoints = endpoints[:50]

# 3. 构造 Mihomo 完整配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
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

# 策略组：由客户端本地定时发送 trace 判定哪一个延迟最低
yaml_lines.extend([
    "proxy-groups:",
    "  - name: WARP-AUTO",
    "    type: url-test",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "",
    "rules:",
    "  - MATCH,WARP-AUTO"
])

with open("warp.yaml", "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"成功生成配置，包含 {len(endpoints)} 个节点！")
