#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re


def load_warp_credentials():
    """从 warpscout 生成的 best-mihomo.yaml 中提取认证参数"""
    creds = {
        "private_key": "",
        "public_key": "",
        "ip": "172.16.0.2",
    }

    if os.path.exists("best-mihomo.yaml"):
        with open("best-mihomo.yaml", "r", encoding="utf-8") as f:
            content = f.read()

            # 正则匹配私钥、公钥和分配的客户端 IP
            priv_m = re.search(r"private-key:\s*([^\s]+)", content)
            pub_m = re.search(r"public-key:\s*([^\s]+)", content)
            ip_m = re.search(r"ip:\s*([^\s]+)", content)

            if priv_m:
                creds["private_key"] = priv_m.group(1).strip()
            if pub_m:
                creds["public_key"] = pub_m.group(1).strip()
            if ip_m:
                creds["ip"] = ip_m.group(1).strip()

    if not creds["private_key"] or not creds["public_key"]:
        print("[!] 警告: 未能从 best-mihomo.yaml 中读取到完整的 WARP 凭证，使用占位凭证")

    return creds


def load_endpoints():
    """解析 endpoints.txt，同时兼容 IPv4、域名及 #备注"""
    endpoints = []
    if os.path.exists("endpoints.txt"):
        with open("endpoints.txt", "r", encoding="utf-8") as f:
            idx = 1
            for line in f:
                line = line.strip()
                # 过滤空行及纯注释行
                if not line or line.startswith("#"):
                    continue

                # 正则解析：兼容域名和 IP 格式，支持末尾 #备注
                # 示例匹配：
                # 162.159.198.2:443
                # 43.129.179.241:8443#🇭🇰 香港1
                # masque-sg1.bestcf.eu.cc:443
                match = re.match(
                    r"^([a-zA-Z0-9\.\-_]+):(\d{1,5})(?:#(.*))?$", line
                )
                if match:
                    server, port, remark = match.groups()
                    port = int(port)

                    # 如果未提供 #备注，则自动生成规范名称
                    if remark and remark.strip():
                        node_name = remark.strip()
                    else:
                        node_name = f"WARP直连-{idx:02d} | {server} | {port}"

                    endpoints.append(
                        {"name": node_name, "server": server, "port": port}
                    )
                    idx += 1

    # 兜底默认节点
    if not endpoints:
        print("[!] 警告: endpoints.txt 中未找到有效节点，使用默认端点")
        endpoints = [
            {
                "name": "WARP直连-01 | 162.159.198.2 | 443",
                "server": "162.159.198.2",
                "port": 443,
            },
            {
                "name": "WARP直连-02 | 162.159.197.2 | 443",
                "server": "162.159.197.2",
                "port": 443,
            },
        ]

    return endpoints


def generate_config():
    creds = load_warp_credentials()
    endpoints = load_endpoints()

    # 收集节点名称供策略组引用
    proxy_names = [ep["name"] for ep in endpoints]
    proxy_names_yaml = "\n".join([f'      - "{name}"' for name in proxy_names])

    # 1. 构建头部及 DNS 基础设置
    config_content = f"""mixed-port: 7890
allow-lan: true
bind-address: '*'
mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true
geodata-mode: true
geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
  geosite: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
geo-auto-update: true
geo-update-interval: 24
global-ua: clash.meta

dns:
  enable: true
  ipv6: false
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.arpa"
    - time.*.com
    - ntp.*.com
    - +.market.xiaomi.com
    - localhost.ptlogin2.qq.com
    - "*.msftncsi.com"
    - www.msftconnecttest.com
  use-hosts: true
  cache-algorithm: arc
  prefer-h3: true
  respect-rules: true

  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29

  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query

  nameserver-policy:
    "geosite:cn":
      - https://dns.alidns.com/dns-query
      - https://doh.pub/dns-query
    "geosite:geolocation-!cn":
      - https://cloudflare-dns.com/dns-query#proxy=端点选择
      - https://dns.google/dns-query#proxy=端点选择

  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29

proxy-groups:
  - name: 端点选择
    type: select
    proxies:
      - 自动选择
      - 故障转移
{proxy_names_yaml}
    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Static.png"

  - name: 自动选择
    type: url-test
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    tolerance: 30
    proxies:
{proxy_names_yaml}
    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Auto.png"

  - name: 故障转移
    type: fallback
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    proxies:
{proxy_names_yaml}
    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png"

  - name: 全球直连
    type: select
    proxies: [DIRECT]
    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Direct.png"

  - name: 全球拦截
    type: select
    proxies: [REJECT, 端点选择, DIRECT]
    icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Reject.png"

rules:
  - GEOIP,private,DIRECT
  - GEOSITE,private,DIRECT
  - GEOSITE,category-ads-all,全球拦截
  - GEOSITE,gfw,端点选择
  - GEOSITE,cn,全球直连
  - GEOIP,CN,全球直连
  - MATCH,端点选择

proxies:
"""

    # 2. 循环追加 proxies 列表
    for ep in endpoints:
        proxy_block = f"""  - name: "{ep['name']}"
    type: masque
    server: {ep['server']}
    port: {ep['port']}
    private-key: {creds['private_key']}
    public-key: {creds['public_key']}
    ip: {creds['ip']}
    mtu: 1280
    udp: true
    remote-dns-resolve: true
    congestion-controller: bbr
    dns: [ 1.1.1.1, 8.8.8.8 ]
    sni: www.microsoft.com

"""
        config_content += proxy_block

    # 3. 输出文件
    with open("warp.yaml", "w", encoding="utf-8") as f:
        f.write(config_content)

    print(
        f"[✓] 成功生成 warp.yaml，共加载 {len(endpoints)} 个 MASQUE 端点节点！"
    )


if __name__ == "__main__":
    generate_config()
