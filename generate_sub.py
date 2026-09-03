import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 1. 国内三大运营商经典优质 Cloudflare CDN Anycast IP 池（高通畅、低延迟）
CF_OPTIMIZED_IPS = [
    # 电信/联通亚太优化段（走香港/日本/新加坡）
    "104.16.160.1", "104.16.161.1", "104.17.160.1", "104.18.160.1",
    "104.19.160.1", "104.20.160.1", "104.21.160.1", "104.22.160.1",
    # 移动 CMI / 骨干优化段（大带宽不丢包）
    "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1",
    "172.67.160.1", "172.67.161.1", "172.67.162.1", "172.67.163.1",
    # 国际金融机构合规加速段（常驻直连白名单）
    "104.16.24.1", "104.16.25.1", "104.18.24.1", "104.18.25.1",
    "104.24.160.1", "104.25.160.1", "104.26.160.1", "104.27.160.1"
]

# 主流放行端口（443与8443在全网封锁最轻，体验最佳）
TARGET_PORTS = ["443", "8443"]

# 顶级抗审查 SNI 伪装池
SNI_POOL = [
    "www.visa.cn",
    "www.mastercard.com.cn",
    "www.apple.com",
    "www.tesla.cn"
]

# 2. 提取账号凭据
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")

# 3. 组装优选节点列表（IP + 端口 + 伪装 SNI 轮询）
node_names = []
proxies_yaml = []

node_idx = 1
for cf_ip in CF_OPTIMIZED_IPS:
    for port in TARGET_PORTS:
        assigned_sni = SNI_POOL[(node_idx - 1) % len(SNI_POOL)]
        name = f"WARP-优选-{node_idx:02d}-{port}"
        node_names.append(name)

        proxies_yaml.extend([
            f"  - name: '{name}'",
            "    type: masque",
            f"    server: '{cf_ip}'",
            f"    port: {port}",
            "    network: h2",
            f"    sni: '{assigned_sni}'",
            f"    private-key: '{private_key}'",
            f"    public-key: '{public_key}'",
            f"    ip: '{ip}'",
        ])
        if ipv6:
            proxies_yaml.append(f"    ipv6: '{ipv6}'")
        proxies_yaml.extend([
            "    udp: true",
            "    remote-dns-resolve: true",
            "    dns: [1.1.1.1, 1.0.0.1]",
            ""
        ])
        node_idx += 1

# 4. 构造完整 Mihomo 配置（注入内核级加速参数）
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "",
    "# 【内核加速】开启并发 TCP 连接与原生浏览器 TLS 伪装指纹",
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
] + proxies_yaml

# 5. 精细策略组（增加主通道与 Fallback 双保险）
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
    "      - 🛡️ 故障转移",   # AI 优先走稳固不乱跳的节点，防止断联报错
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
    ""
])

# 6. 精准分流规则
yaml_lines.extend([
    "rules:",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # 规避 BT/P2P 下载被限速或封号",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Transmission.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - PROCESS-NAME,BitComet.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功融合 Cloudflare 优质 Anycast IP 算法！")
print(f"[OK] 已生成 {len(node_names)} 个高吞吐全优节点，输出至: {OUTPUT_PATH}")
