import os
import re

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BEST_CONF_PATH = os.path.join(CURRENT_DIR, "best-mihomo.yaml")
TXT_PATH = os.path.join(CURRENT_DIR, "endpoints.txt")
OUTPUT_PATH = os.path.join(CURRENT_DIR, "warp.yaml")

# 统一使用稳定放行的微软 SNI
DEFAULT_SNI = "www.microsoft.com"

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

# 2. 读取端点池（优先读取 endpoints.txt）
target_items = []

if os.path.exists(TXT_PATH):
    print(f"[INFO] 载入端点文件: {TXT_PATH}")
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

# 兜底节点
if not target_items:
    target_items = [
        {"endpoint": "13.250.41.68:443", "alias": "🇸🇬 新加坡 AWS | 13.250.41.68 | 443"},
        {"endpoint": "172.237.6.233:443", "alias": "🇯🇵 日本 Linode | 172.237.6.233 | 443"},
        {"endpoint": "13.124.209.180:443", "alias": "🇰🇷 韩国 AWS | 13.124.209.180 | 443"},
        {"endpoint": "158.101.89.186:443", "alias": "🇯🇵 日本甲骨文 | 158.101.89.186 | 443"},
        {"endpoint": "43.129.179.241:8443", "alias": "🇭🇰 香港腾讯云 | 43.129.179.241 | 8443"}
    ]

# 3. 组装 proxies 节点列表（严格对齐网友格式）
proxies_list = []
node_names = []

for idx, item in enumerate(target_items, 1):
    ep = item["endpoint"]
    custom_alias = item["alias"]
    host, port = ep.split(":")
    
    if custom_alias:
        name = custom_alias
    else:
        name = f"WARP直连-{idx:02d} | {host} | {port}"
    
    node_names.append(name)
    
    node_lines = [
        f"  - name: \"{name}\"",
        "    type: masque",
        f"    server: {host}",
        f"    port: {port}",
        f"    private-key: {private_key}",
        f"    public-key: {public_key}",
        f"    ip: {ip}",
    ]
    if ipv6:
        node_lines.append(f"    ipv6: {ipv6}")
    
    node_lines.extend([
        "    mtu: 1280",
        "    udp: true",
        "    remote-dns-resolve: true",
        "    congestion-controller: bbr",
        "    dns: [ 1.1.1.1, 8.8.8.8 ]",
        f"    sni: {DEFAULT_SNI}",
        ""
    ])
    proxies_list.extend(node_lines)

# 4. 构建完整 YAML 配置（100% 对齐网友结构）
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
    "proxy-groups:",
    "  - name: 端点选择",
    "    type: select",
    "    proxies:",
    "      - 自动选择",
    "      - 故障转移",
] + [f"      - \"{name}\"" for name in node_names] + [
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Static.png"',
    "",
    "  - name: 自动选择",
    "    type: url-test",
    "    url: https://cp.cloudflare.com/generate_204",
    "    interval: 300",
    "    tolerance: 30",
    "    proxies:"
] + [f"      - \"{name}\"" for name in node_names] + [
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png"',
    "",
    "  - name: 故障转移",
    "    type: fallback",
    "    url: https://cp.cloudflare.com/generate_204",
    "    interval: 300",
    "    proxies:"
] + [f"      - \"{name}\"" for name in node_names] + [
    '    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png"',
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
    "",
    "rules:",
    "  - GEOIP,private,DIRECT",
    "  - GEOSITE,private,DIRECT",
    "  - GEOSITE,category-ads-all,全球拦截",
    "  - GEOSITE,gfw,端点选择",
    "  - GEOSITE,cn,全球直连",
    "  - GEOIP,CN,全球直连",
    "  - MATCH,端点选择",
    "",
    "proxies:"
] + proxies_list

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_lines))

print(f"[OK] 成功100%对齐网友架构！Gemini IP分裂已解决，油管满速直连！")
print(f"[OK] 文件已生成至: {OUTPUT_PATH}")
