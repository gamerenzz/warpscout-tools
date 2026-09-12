import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
TXT_PATH = os.path.join(CURRENT_DIR, "endpoints.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 顶级 SNI 伪装池（加入最新官方原生支持 ECH 的 kitesurf 域名）
SNI_POOL = [
    "kitesurf.cloudflare.app",    # 【最新官方玩具】原生支持 ECH 的正版 CF 域名，特征最纯净
    "www.visa.cn",                # 金融免封白名单
    "www.apple.com",              # 苹果主流服务白名单
    "www.tesla.cn"                # 跨国车企白名单
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
target_items = []  # 存储结构: [{"endpoint": "ip:port", "alias": "自定义别名或None"}]

if os.path.exists(TXT_PATH):
    print(f"[INFO] 载入本地端点文件: {TXT_PATH}")
    with open(TXT_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # 提取备注
            alias = None
            if "#" in line:
                parts = line.split("#", 1)
                line = parts[0].strip()
                alias = parts[1].strip()
            
            # 正则匹配 IP:Port
            m = re.match(r'^((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})', line)
            if m:
                ep = m.group(1)
                if not any(item["endpoint"] == ep for item in target_items):
                    target_items.append({"endpoint": ep, "alias": alias})

if not target_items:
    # 基础兜底
    target_items = [
        {"endpoint": "162.159.199.144:4443", "alias": None},
        {"endpoint": "162.159.198.88:8443", "alias": None},
        {"endpoint": "162.159.198.187:1701", "alias": None},
        {"endpoint": "162.159.198.214:8095", "alias": None}
    ]

# 3. 解析 Opera 落地节点信息
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

# 4. 组装代理底座 (智能赋予节点名称)
underlying_proxies = []
underlying_names = []
special_ai_proxies = []  # 专门供 AI 手动直连选用的亚太反代节点

for idx, item in enumerate(target_items, 1):
    ep = item["endpoint"]
    custom_alias = item["alias"]
    host, port = ep.split(":")
    assigned_sni = SNI_POOL[(idx - 1) % len(SNI_POOL)]
    
    # 命名逻辑：若有别名使用自定义别名，否则自动编号
    if custom_alias:
        name = custom_alias
        special_ai_proxies.append(name)  # 记录进专属列表
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
        "    dns: [1.1.1.1, 1.0.0.1]",
        ""
    ])

# 笛卡尔积组合套娃节点 (只取前 8 个端点当底座，防止节点膨胀)
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

# 5. 构建完整 YAML 配置
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
    "    - https://223.5.5.5/dns-query",
    "    - https://1.12.12.12/dns-query",
    "  proxy-server-nameserver:",
    "    - https://223.5.5.5/dns-query",
    "  nameserver-policy:",
    "    'geosite:cn,private':",
    "      - https://223.5.5.5/dns-query",
    "    'geosite:geolocation-!cn':",
    "      - https://1.1.1.1/dns-query",
    "      - https://8.8.8.8/dns-query",
    "",
    "proxies:"
] + underlying_proxies + combo_proxies

# 6. 精细化策略组架构
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
    "    url: https://www.cloudflare.com/cdn-cgi/trace",
    "    interval: 300",
    "    tolerance: 50",
    "    lazy: true",
    "    proxies:"
] + [f"      - '{name}'" for name in underlying_names] + [
    "",
    "  # 【AI专用组】不仅能走套娃地区线路，还能直接单选亚太极速落地！",
    "  - name: 🤖 人工智能",
    "    type: select",
    "    proxies:",
    "      - 🗽 美洲线路",
    "      - 🌍 欧洲线路",
    "      - ⚡ 亚洲线路",
] + [f"      - '{name}'" for name in special_ai_proxies] + [
    "      - ⚡ WARP极速优选",
    "",
    "  # 【苹果海外服务】专门针对海外 App Store，强制美洲/海外套娃IP，避开被踢回国区",
    "  - name: 🍎 苹果服务",
    "    type: select",
    "    proxies:",
    "      - 🗽 美洲线路",
    "      - ⚡ 亚洲线路",
    "      - 🌍 欧洲线路",
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

# 7. 全场景高精分流规则
yaml_lines.extend([
    "rules:",
    "  # 1. 彻底阻断 QUIC，避免 UDP 死锁与降速",
    "  - AND,((DST-PORT,443),(NETWORK,UDP)),REJECT",
    "",
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
    "  # 2. 苹果海外商店全套 API 与静态资源，强制走代理！防止被误判回国区",
    "  - DOMAIN-SUFFIX,apps.apple.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,itunes.apple.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,mzstatic.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,aaplimg.com,🍎 苹果服务",
    "  - DOMAIN-SUFFIX,appsto.re,🍎 苹果服务",
    "  - DOMAIN,amp-api.music.apple.com,🍎 苹果服务",
    "",
    "  # 3. AI 服务专属分流",
    "  - DOMAIN-SUFFIX,bard.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,gemini.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,aistudio.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,ai.google.dev,🤖 人工智能",
    "  - DOMAIN-SUFFIX,makersuite.google.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,deepmind.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,deepmind.google,🤖 人工智能",
    "  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,alkalimakersuite-pa.googleapis.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,proactivebackend-pa.googleapis.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,apis.google.com,🤖 人工智能",
    "  - DOMAIN-KEYWORD,alkali,🤖 人工智能",
    "  - DOMAIN-KEYWORD,gemini,🤖 人工智能",
    "  - DOMAIN-KEYWORD,bard,🤖 人工智能",
    "  - DOMAIN-KEYWORD,colab,🤖 人工智能",
    "  - GEOSITE,openai,🤖 人工智能",
    "  - DOMAIN-SUFFIX,chatgpt.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaistatic.com,🤖 人工智能",
    "  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 人工智能",
    "  - GEOSITE,anthropic,🤖 人工智能",
    "  - DOMAIN-SUFFIX,claude.ai,🤖 人工智能",
    "",
    "  # 4. 普通 Google 生态",
    "  - DOMAIN-SUFFIX,googleapis.com,🚀 默认代理",
    "  - DOMAIN-SUFFIX,gstatic.com,🚀 默认代理",
    "  - DOMAIN-SUFFIX,google.com,🚀 默认代理",
    "  - DOMAIN-SUFFIX,googleusercontent.com,🚀 默认代理",
    "",
    "  # 5. 海外多媒体",
    "  - GEOSITE,youtube,📺 国际媒体",
    "  - GEOSITE,netflix,📺 国际媒体",
    "  - GEOSITE,spotify,📺 国际媒体",
    "",
    "  # 6. 大陆直连白名单",
    "  - GEOSITE,cn,DIRECT",
    "  - GEOSITE,category-games@cn,DIRECT",
    "  - GEOIP,CN,DIRECT",
    "",
    "  # 7. 兜底",
    "  - MATCH,🚀 默认代理"
])

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功融合官方 kitesurf 原生伪装与亚太中继！已写入 {len(target_items)} 个底座端点至: {OUTPUT_PATH}")
print(f"[OK] 包含专属节点: {special_ai_proxies}")
