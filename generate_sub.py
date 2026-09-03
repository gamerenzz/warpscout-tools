import os
import re
from collections import defaultdict

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
REPORT_PATH = os.path.join(CURRENT_DIR, "scan-report.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 1. 异构高信誉 SNI 池（兼顾隐蔽与大带宽放行）
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

# 3. 提取端点与真实地理机房（解决：不知道落在哪里的问题）
endpoints_info = []
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
        
        # 提取：IP:端口、端点Ping、出口机房(如 HKG, NRT, SJC)
        parts = line.split()
        if len(parts) >= 6:
            ep = parts[0]
            # 验证合法 ip:port
            if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}$', ep):
                colo = parts[5] if len(parts) > 5 else "CF"
                endpoints_info.append({"ep": ep, "colo": colo})

# 4. 【速度核心优化】亚太优先排序算法
# 离国内最近的顶级机房名单（优先挑这些，速度直接提升数倍）
AP_COLOS = ["HKG", "NRT", "HND", "KIX", "ICN", "SIN", "TPE"]

ap_endpoints = [x for x in endpoints_info if any(ap in x['colo'].upper() for ap in AP_COLOS)]
other_endpoints = [x for x in endpoints_info if x not in ap_endpoints]

# 优先塞入亚太节点，剩下的再用其他优质节点补充
sorted_candidates = ap_endpoints + other_endpoints

# 5. 端口均衡提取前 35 个（聚焦最快、最不拥堵的 443 和 8443）
port_buckets = defaultdict(list)
for item in sorted_candidates:
    port = item["ep"].split(":")[1]
    port_buckets[port].append(item)

balanced_nodes = []
# 翻墙实测中：443 和 8443 的 TCP 拥塞表现最好，丢包最少
priority_ports = ["443", "8443", "1701", "4443", "8095"]
for p in port_buckets.keys():
    if p not in priority_ports:
        priority_ports.append(p)

while len(balanced_nodes) < 35:
    added = False
    for p in priority_ports:
        if port_buckets[p]:
            balanced_nodes.append(port_buckets[p].pop(0))
            added = True
            if len(balanced_nodes) >= 35:
                break
    if not added:
        break

# 6. 生成为“速度与稳定性”定制的完整配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "# 【稳定性核心】开启 TCP 并发提升首字响应速度，优化 TCP 堆栈",
    "tcp-concurrent: true",
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  # 国内走极速纯净 DNS，防止抢占国外连接带宽",
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
for idx, item in enumerate(balanced_nodes, 1):
    ep = item["ep"]
    colo = item["colo"]
    host, port = ep.split(":")
    sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    
    # 节点名打上机房标签（如 WARP-01-443 [HKG]），面板一清二楚
    name = f"WARP-{idx:02d}-{port} [{colo}]"
    node_names.append(name)

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

# 7. 策略组架构设计（彻底解决断流与横跳）
yaml_lines.extend([
    "proxy-groups:",
    "  # 主通道：绑定到【稳定主力】，告别频繁掉线",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - 🛡️ 稳定主力",
    "      - ⚡ 极速选优",
    "      - DIRECT",
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  # 【稳定性核心：Fallback】按顺序只用第一个节点，完全不断流、不换IP！",
    "  # 只有当第一个节点彻底超时炸了，才丝滑切到第二个备用",
    "  - name: 🛡️ 稳定主力",
    "    type: fallback",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 180",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  # 【速度核心：url-test】给需要大带宽（看 4K 视频、大文件下载）的场景使用",
    "  - name: ⚡ 极速选优",
    "    type: url-test",
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 100", # 容差拉高到 100ms，只要节点不严重降速，不轻易乱跳
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in node_names] + [
    "",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
    "      - 🛡️ 稳定主力",  # AI 最怕换 IP，必须走稳定主力
    "      - ⚡ 极速选优",
    "",
    "  - name: 📺 国际流媒体",
    "    type: select",
    "    proxies:",
    "      - ⚡ 极速选优",  # 视频最要速度，走极速选优
    "      - 🛡️ 稳定主力",
    "",
    "  - name: 🛑 广告拦截",
    "    type: select",
    "    proxies:",
    "      - REJECT",
    "      - DIRECT",
    ""
])

# 8. 极简高效分流（直击提速）
yaml_lines.extend([
    "rules:",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # P2P 下载彻底直连，保护代理带宽与防限速",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "",
    "  # 广告拦截，省下无谓流量",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "",
    "  # 专项分流",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - GEOSITE,youtube,📺 国际流媒体",
    "  - GEOSITE,netflix,📺 国际流媒体",
    "",
    "  # 国内全直连",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 兜底",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 速度与稳定增强配置已生成: {OUTPUT_PATH}")
print(f"[OK] 亚太优先节点提取完成，包含 {len(balanced_nodes)} 个精选端点！")
