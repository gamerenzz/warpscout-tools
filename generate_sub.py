import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
TXT_PATH = os.path.join(CURRENT_DIR, "endpoints.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

SNI_POOL = [
    "www.microsoft.com",
    "kitesurf.cloudflare.app",
    "www.visa.cn",
    "www.apple.com"
]

# 1. 提取 WARP 凭据
with open(BEST_CONF_PATH, "r", encoding="utf-8") as f:
    best_content = f.read()

def get_val(key):
    m = re.search(rf'^\s*{key}\s*:\s*(\S+)', best_content, re.M)
    return m.group(1).strip("'\"") if m else None

private_key = get_val("private-key")
public_key = get_val("public-key")
ip = get_val("ip")
ipv6 = get_val("ipv6")

# 2. 读取端点池与自定义别名
target_items = []

if os.path.exists(TXT_PATH):
    print(f"[INFO] 载入本地端点文件: {TXT_PATH}")
    with open(TXT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            alias = None
            if "#" in line:
                parts = line.split("#", 1)
                line = parts[0].strip()
                alias = parts[1].strip()
            
            m = re.match(r'^((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})', line)
            if m:
                ep = m.group(1)
                if not any(item["endpoint"] == ep for item in target_items):
                    target_items.append({"endpoint": ep, "alias": alias})

if not target_items:
    target_items = [
        {"endpoint": "162.159.199.144:4443", "alias": None},
        {"endpoint": "162.159.198.88:8443", "alias": None},
        {"endpoint": "162.159.198.187:1701", "alias": None}
    ]

# 3. 解析 Opera 落地节点信息
def parse_opera(filename, region_name):
    path = os.path.join(CURRENT_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    login_m = re.search(r"Proxy login: (\S+)", content)
    pw_m = re.search(r"Proxy password: (\S+)", content)
    if not (login_m and pw_m):
        return []
    
    user, pw = login_m.group(1), pw_m.group(1)
    landings = []
    seq = 1
    for line in content.splitlines():
        m = re.match(r"^([\w.-]+\.sec-tunnel\.com),([\d.]+),(\d+)$", line.strip())
        if m:
            host, srv_ip, port = m.groups()
            landings.append({
                "tag": f"{region_name}{seq}",
                "host": host,
                "ip": srv_ip,
                "port": port,
                "user": user,
                "pw": pw
            })
            seq += 1
    return landings

opera_as = parse_opera("opera_as.txt", "亚洲")
opera_eu = parse_opera("opera_eu.txt", "欧洲")
opera_am = parse_opera("opera_am.txt", "美洲")

# 4. 组装第一层代理底座 (WARP 直连 / 亚太自建)
underlying_proxies = []
underlying_names = []

for idx, item in enumerate(target_items, 1):
    ep = item["endpoint"]
    custom_alias = item["alias"]
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    
    if custom_alias:
        name = custom_alias
    else:
        name = f"WARP直连-{idx:02d}"
    
    underlying_names.append(name)
    underlying_proxies.extend([
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
        underlying_proxies.append(f"    ipv6: '{ipv6}'")
    underlying_proxies.extend([
        "    mtu: 1280",
        "    udp: true",
        "    remote-dns-resolve: true",
        "    congestion-controller: bbr",
        "    dns: [ 1.1.1.1, 8.8.8.8 ]",
        ""
    ])

# 5. 组装第二层套娃节点 (Opera over MASQUE)
opera_combo_proxies = []
opera_node_names = []

# 挑选底层最快的前 4 个端点作为套娃底座
base_anchors = underlying_names[:4]

all_landings = [("亚洲", opera_as), ("欧洲", opera_eu), ("美洲", opera_am)]
for reg_name, landings in all_landings:
    if not landings:
        continue
    for land in landings[:2]:  # 每个大区挑前 2 个服务器
        for base_name in base_anchors:
            c_name = f"Opera-{land['tag']}@{base_name}"
            opera_node_names.append(c_name)
            opera_combo_proxies.append(
                f"  - {{name: '{c_name}', type: http, server: {land['ip']}, port: {land['port']}, "
                f"username: {land['user']}, password: {land['pw']}, tls: true, sni: {land['host']}, "
                f"skip-cert-verify: false, dialer-proxy: '{base_name}'}}"
            )

# 6. 构建完整配置基础
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: true",
    "bind-address: '*'",
    "mode: rule",
    "log-level: info",
    "ipv6: false",
    "unified-delay: true",
    "tcp-concurrent: true",
    "geodata-mode: true",
    "geox-url:",
    '  geoip: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"',
    '  geosite: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"',
    "geo-auto-update: true",
    "geo-update-interval: 24",
    "global-ua: clash.meta",
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  listen: 0.0.0.0:1053",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  fake-ip-filter:",
    '    - "*.lan"',
    '    - "*.local"',
    '    - "*.arpa"',
    "    - time.*.com",
    "    - ntp.*.com",
    "    - +.market.xiaomi.com",
    "    - localhost.ptlogin2.qq.com",
    '    - "*.msftncsi.com"',
    "    - www.msftconnecttest.com",
    "  use-hosts: true",
    "  cache-algorithm: arc",
    "  prefer-h3: true",
    "  respect-rules: true",
    "",
    "  default-nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "",
    "  nameserver:",
    "    - https://dns.alidns.com/dns-query",
    "    - https://doh.pub/dns-query",
    "",
    "  nameserver-policy:",
    '    "geosite:cn":',
    "      - https://dns.alidns.com/dns-query",
    "      - https://doh.pub/dns-query",
    '    "geosite:geolocation-!cn":',
    "      - https://cloudflare-dns.com/dns-query#proxy=端点选择",
    "      - https://dns.google/dns-query#proxy=端点选择",
    "",
    "  proxy-server-nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "",
    "proxies:"
] + underlying_proxies + opera_combo_proxies

# 7. 构造精细策略组 (增加 Opera 套娃独立组，将测速源指向 Google 解决油管卡顿)
all_test_proxies = underlying_names + opera_node_names

yaml_lines.extend([
    "",
    "proxy-groups:",
    "  - name: 端点选择",
    "    type: select",
    "    proxies:",
    "      - 自动选择",
    "      - 故障转移",
    "      - 🎭 Opera套娃落地",
] + [f"      - '{name}'" for name in underlying_names] + [
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Static.png"',
    "",
    "  # 【核心提速】：用 Google 原生 generate_204 测速，确保选出看油管最快的节点",
    "  - name: 自动选择",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 30",
    "    proxies:"
] + [f"      - '{name}'" for name in all_test_proxies] + [
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png"',
    "",
    "  - name: 故障转移",
    "    type: fallback",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    proxies:"
] + [f"      - '{name}'" for name in all_test_proxies] + [
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png"',
    "",
    "  # 【Opera 专属组】：可随时在此切到纯正海外落地，或交由组内自动选优",
    "  - name: 🎭 Opera套娃落地",
    "    type: select",
    "    proxies:",
    "      - 🎭 Opera自动选优",
] + [f"      - '{name}'" for name in opera_node_names] + [
    "",
    "  - name: 🎭 Opera自动选优",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in opera_node_names] + [
    "",
    "  - name: 全球直连",
    "    type: select",
    "    proxies: [DIRECT]",
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Direct.png"',
    "",
    "  - name: 全球拦截",
    "    type: select",
    "    proxies: [REJECT, 端点选择, DIRECT]",
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Reject.png"',
    ""
])

# 8. 高效防分裂分流规则（含封杀 QUIC 提速补丁）
yaml_lines.extend([
    "rules:",
    "  # 1. 【核心提速】：封杀 UDP 443 (QUIC)，逼迫 YouTube/Google 走满速 TCP H2",
    "  - AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    "",
    "  - GEOIP,private,DIRECT",
    "  - GEOSITE,private,DIRECT",
    "",
    "  # 2. 规避 BT/P2P 下载被限速",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "",
    "  # 3. 广告过滤",
    "  - GEOSITE,category-ads-all,全球拦截",
    "",
    "  # 4. GFW 统一整流走端点选择（彻底杜绝 Gemini/Google 异地 IP 分裂）",
    "  - GEOSITE,gfw,端点选择",
    "",
    "  # 5. 国内白名单",
    "  - GEOSITE,cn,全球直连",
    "  - GEOIP,CN,全球直连",
    "",
    "  # 6. 兜底",
    "  - MATCH,端点选择"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功融合 Opera 专属组与 YouTube QUIC 极速补丁！")
print(f"[OK] 包含底座节点 {len(underlying_names)} 个，Opera 套娃节点 {len(opera_node_names)} 个！")
print(f"[OK] 已输出完整配置至: {OUTPUT_PATH}")
