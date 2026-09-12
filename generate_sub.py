import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
TXT_PATH = os.path.join(CURRENT_DIR, "endpoints.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

SNI_POOL = [
    "kitesurf.cloudflare.app",
    "www.visa.cn",
    "www.apple.com",
    "www.tesla.cn"
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

# 2. 读取端点池
target_items = []
if os.path.exists(TXT_PATH):
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
    target_items = [{"endpoint": "162.159.199.144:4443", "alias": None}]

# 3. 解析 Opera 落地
def parse_opera(filename, region_name):
    path = os.path.join(CURRENT_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    login_m = re.search(r"Proxy login: (\S+)", content)
    pw_m = re.search(r"Proxy password: (\S+)", content)
    if not (login_m and pw_m):
        return None
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

opera_regions = {
    "亚洲": parse_opera("opera_as.txt", "亚洲"),
    "欧洲": parse_opera("opera_eu.txt", "欧洲"),
    "美洲": parse_opera("opera_am.txt", "美洲")
}

# 4. 组装代理
underlying_proxies = []
underlying_names = []
special_proxies = []

for idx, item in enumerate(target_items, 1):
    ep = item["endpoint"]
    custom_alias = item["alias"]
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    
    if custom_alias:
        name = custom_alias
        special_proxies.append(name)
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
        "    udp: true",
        "    remote-dns-resolve: true",
        "    congestion-controller: bbr",
        "    dns: [1.1.1.1, 8.8.8.8]",
        ""
    ])

combo_proxies = []
region_groups = {"亚洲": [], "欧洲": [], "美洲": []}

for region, landings in opera_regions.items():
    if not landings:
        continue
    for land in landings[:2]:
        for base_name in underlying_names[:8]:
            c_name = f"{land['tag']}@{base_name}"
            region_groups[region].append(c_name)
            combo_proxies.append(
                f"  - {{name: '{c_name}', type: http, server: {land['ip']}, port: {land['port']}, "
                f"username: {land['user']}, password: {land['pw']}, tls: true, sni: {land['host']}, "
                f"skip-cert-verify: false, dialer-proxy: '{base_name}'}}"
            )

# 5. 构建带真实 DNS 代理策略的配置
yaml_lines = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    "ipv6: false",
    "unified-delay: true",
    "tcp-concurrent: true",
    "",
    "sniffer:",
    "  enable: true",
    "  sniff:",
    "    HTTP:",
    "      ports: [80, 8080-8880]",
    "      override-destination: true",
    "    TLS:",
    "      ports: [443, 8443]",
    "  skip-domain:",
    "    - '+.push.apple.com'",
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  fake-ip-filter:",
    "    - '+.lan'",
    "    - '+.local'",
    "    - '*.msftconnecttest.com'",
    "    - '*.msftncsi.com'",
    "  default-nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "  nameserver:",
    "    - https://dns.alidns.com/dns-query",
    "    - https://doh.pub/dns-query",
    "  proxy-server-nameserver:",
    "    - 223.5.5.5",
    "    - 119.29.29.29",
    "  nameserver-policy:",
    "    'geosite:cn':",
    "      - https://dns.alidns.com/dns-query",
    "      - https://doh.pub/dns-query",
    "    # 【关键修复】海外域名解析必须挂接代理，杜绝返回错配 IP",
    "    'geosite:geolocation-!cn':",
    "      - 'https://cloudflare-dns.com/dns-query#proxy=🚀 默认代理'",
    "      - 'https://dns.google/dns-query#proxy=🚀 默认代理'",
    "",
    "proxies:"
] + underlying_proxies + combo_proxies

# 6. 精巧策略组
yaml_lines.extend([
    "",
    "proxy-groups:",
    "  - name: 🚀 默认代理",
    "    type: select",
    "    proxies:",
    "      - ⚡ WARP极速优选",
    "      - 🤖 人工智能",
    "      - 🗽 美洲线路",
    "      - DIRECT",
] + [f"      - '{name}'" for name in underlying_names] + [
    "",
    "  - name: ⚡ WARP极速优选",
    "    type: url-test",
    "    url: https://cp.cloudflare.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in underlying_names] + [
    "",
    "  # 【AI专用组】日本/新加坡反代排前面，支持手动钦定且全套 Google 一起走！",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
] + [f"      - '{name}'" for name in special_proxies] + [
    "      - 🗽 美洲线路",
    "      - 🌍 欧洲线路",
    "      - ⚡ 亚洲线路",
    "      - ⚡ WARP极速优选",
    "",
    "  - name: 🍎 苹果服务",
    "    type: select",
    "    proxies:",
    "      - 🗽 美洲线路",
    "      - ⚡ 亚洲线路",
    "      - ⚡ WARP极速优选",
    "      - DIRECT",
    "",
    "  - name: 🗽 美洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["美洲"]] + [
    "",
    "  - name: 🌍 欧洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["欧洲"]] + [
    "",
    "  - name: ⚡ 亚洲线路",
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in region_groups["亚洲"]] + [
    "",
    "  - name: 📺 国际媒体",
    "    type: select",
    "    proxies:",
    "      - ⚡ WARP极速优选",
    "      - 🚀 默认代理",
    "",
    "  - name: 🛑 广告拦截",
    "    type: select",
    "    proxies:",
    "      - REJECT",
    "      - DIRECT",
    ""
])

# 7. 全场景高精分流规则（【核心修复】彻底消除 IP 分裂）
yaml_lines.extend([
    "rules:",
    "  - AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    "  - GEOIP,private,DIRECT,no-resolve",
    "  - GEOIP,lan,DIRECT,no-resolve",
    "",
    "  # 规避 BT/P2P 下载",
    "  - PROCESS-NAME,qbittorrent.exe,DIRECT",
    "  - PROCESS-NAME,Thunder.exe,DIRECT",
    "  - DST-PORT,6881-6889,DIRECT",
    "  - DST-PORT,123,DIRECT",
    "  - DST-PORT,53,DIRECT",
    "",
    "  # 广告拦截",
    "  - GEOSITE,category-ads-all,🛑 广告拦截",
    "",
    "  # 苹果海外商店全套走代理，杜绝重定向",
    "  - DOMAIN-SUFFIX,apps.apple.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,itunes.apple.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,mzstatic.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,aaplimg.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,appsto.re,🍎 苹果服务",
    "  - DOMAIN,amp-api.music.apple.com,🍎 苹果服务",
    "",
    "  # 【核心修复】Gemini + 所有 Google 基础认证统一走【🤖 人工智能】，杜绝前后台 IP 分裂！",
    "  - GEOSITE,google,🤖 人工智能",
    "  - DOMAIN-SUFFIX,google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,googleapis.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,gstatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,googleusercontent.com,🤖 人工智能",
    "  - DOMAIN-KEYWORD,gemini,🤖 人工智能",
    "  - DOMAIN-KEYWORD,bard,🤖 人工智能",
    "",
    "  # OpenAI / ChatGPT / Claude",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - DOMAIN-SUFFIX,chatgpt.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,claude.ai,🤖 人工智能",
    "",
    "  # 海外多媒体",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "",
    "  # 大陆直连白名单",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 兜底",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功修复 Gemini 无法打开的问题！DNS 代理联动与防 IP 分裂已就绪！")
