#!/usr/bin/env python3
"""
Github根目录版黑名单处理器
位置：/data/python/blacklist_processor.py
输入：/adblock.txt (根目录)
输出：/dns.txt 和 /hosts.txt (根目录)
"""

import os
import re
import sys
import time
import logging
import threading
from pathlib import Path
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import dns.resolver
import dns.message
import dns.rdatatype
import ssl
import socket
from typing import Tuple, List, Set, Optional, Dict

# ======================
# 路径配置
# ======================
def get_repo_root() -> Path:
    """自动获取仓库根目录（向上3层）"""
    return Path(__file__).parent.parent.parent

ROOT = get_repo_root()  # 仓库根目录

# 输入输出文件路径（直接放在根目录）
INPUT_FILE = ROOT / "adblock.txt"
OUTPUT_ADGUARD = ROOT / "dns.txt"
OUTPUT_HOSTS = ROOT / "hosts.txt"

# ======================
# 日志配置（仅控制台）
# ======================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class Config:
    """配置中心"""
    def __init__(self):
        # 文件路径
        self.INPUT_FILE = INPUT_FILE
        self.OUTPUT_ADGUARD = OUTPUT_ADGUARD
        self.OUTPUT_HOSTS = OUTPUT_HOSTS

        # 功能开关
        self.DNS_VALIDATION = True
        self.WHOIS_ENABLED = False
        self.IS_CI = os.getenv("CI", "false").lower() == "true"

        # DNS服务器配置
        self.DNS_SERVERS = {
            "cn": [
                {"doh": "https://dns.alidns.com/dns-query", "udp": "223.5.5.5"},
                {"doh": "https://doh.pub/dns-query", "udp": "119.29.29.29"},
                {"udp": "223.6.6.6"}
            ],
            "intl": [
                {"doh": "https://cloudflare-dns.com/dns-query", "udp": "1.1.1.1"},
                {"doh": "https://dns.google/dns-query", "udp": "8.8.8.8"}
            ]
        }

        # 性能配置
        self.MAX_WORKERS = 4 if self.IS_CI else 8
        self.BATCH_SIZE = 5000 if self.IS_CI else 10000
        self.DNS_TIMEOUT = 2 if self.IS_CI else 5
        self.DNS_RETRIES = 1 if self.IS_CI else 2

    def validate_paths(self):
        """验证路径有效性"""
        if not self.INPUT_FILE.exists():
            raise FileNotFoundError(f"输入文件不存在: {self.INPUT_FILE}")
        self.OUTPUT_ADGUARD.parent.mkdir(exist_ok=True)  # 确保根目录可写

class BlacklistProcessor:
    """黑名单处理核心"""
    REGEX_PATTERNS = {
        'hosts_comment': re.compile(r"#.*$"),
        'hosts_split': re.compile(r"\s+"),
        'adguard': re.compile(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$|/)"),
        'wildcard': re.compile(r"^\*\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"),
        'exclusions': re.compile(r"^(@@|#|!)")
    }

    def __init__(self):
        self.config = Config()
        self.config.validate_paths()
        self._init_resolvers()
        self.valid_adguard = set()
        self.valid_hosts = set()
        self.total_processed = 0
        self.start_time = time.time()

    def _init_resolvers(self):
        """初始化DNS解析器"""
        self.resolvers = {
            'doh': [],
            'udp': {}
        }
        for group in self.config.DNS_SERVERS.values():
            for server in group:
                if 'doh' in server:
                    self.resolvers['doh'].append(server['doh'])
                if 'udp' in server:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [server['udp']]
                    resolver.timeout = self.config.DNS_TIMEOUT
                    self.resolvers['udp'][server['udp']] = resolver

    def _doh_query(self, server: str, domain: str) -> bool:
        """DoH查询"""
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            wire_data = base64.urlsafe_b64encode(query.to_wire()).decode().rstrip("=")
            resp = requests.get(
                f"{server}?dns={wire_data}",
                headers={"Accept": "application/dns-message"},
                timeout=self.config.DNS_TIMEOUT
            )
            return len(dns.message.from_wire(resp.content).answer) > 0
        except Exception:
            return False

    def _udp_query(self, server: str, domain: str) -> bool:
        """UDP查询"""
        try:
            self.resolvers['udp'][server].resolve(domain, "A")
            return True
        except Exception:
            return False

    def _is_domain_valid(self, domain: str) -> bool:
        """验证域名有效性"""
        if not self.config.DNS_VALIDATION:
            return True

        # 尝试DoH查询
        for server in self.resolvers['doh']:
            if self._doh_query(server, domain):
                return True

        # 回退到UDP查询
        for server in self.resolvers['udp']:
            if self._udp_query(server, domain):
                return True

        return False

    def _parse_line(self, line: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """解析单行规则"""
        line = line.strip()
        if not line or self.REGEX_PATTERNS['exclusions'].match(line):
            return None, None

        # 解析AdGuard规则
        if match := self.REGEX_PATTERNS['adguard'].match(line):
            domain = match.group(1)
            if self._is_domain_valid(domain):
                return line, [f"0.0.0.0 {domain}"]

        # 解析Hosts规则
        if " " in line:
            parts = self.REGEX_PATTERNS['hosts_split'].split(
                self.REGEX_PATTERNS['hosts_comment'].sub("", line)
            )
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                valid_domains = [d for d in parts[1:] if self._is_domain_valid(d)]
                if valid_domains:
                    new_line = f"{parts[0]} {' '.join(valid_domains)}"
                    return new_line, [f"{parts[0]} {d}" for d in valid_domains]

        return None, None

    def process(self):
        """主处理流程"""
        logger.info(f"开始处理: {self.config.INPUT_FILE}")
        logger.info(f"输出文件: {self.config.OUTPUT_ADGUARD} | {self.config.OUTPUT_HOSTS}")
        
        with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
            futures = []
            with open(self.config.INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    futures.append(executor.submit(self._parse_line, line))
                    if len(futures) >= self.config.BATCH_SIZE:
                        self._process_batch(futures)
                        futures = []
            
            if futures:
                self._process_batch(futures)

        self._save_results()
        self._print_summary()

    def _process_batch(self, futures):
        """处理批次结果"""
        for future in as_completed(futures):
            adguard_rule, hosts_rules = future.result()
            if adguard_rule:
                self.valid_adguard.add(adguard_rule)
            if hosts_rules:
                self.valid_hosts.update(hosts_rules)
            self.total_processed += 1

            if self.total_processed % 1000 == 0:
                self._log_progress()

    def _log_progress(self):
        """打印进度"""
        elapsed = time.time() - self.start_time
        rate = self.total_processed / elapsed if elapsed > 0 else 0
        logger.info(
            f"已处理: {self.total_processed} | "
            f"AdGuard规则: {len(self.valid_adguard)} | "
            f"Hosts规则: {len(self.valid_hosts)} | "
            f"速度: {rate:.1f} 条/秒"
        )

    def _save_results(self):
        """保存结果文件"""
        with open(self.config.OUTPUT_ADGUARD, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.valid_adguard)))
        
        with open(self.config.OUTPUT_HOSTS, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.valid_hosts)))

    def _print_summary(self):
        """打印最终摘要"""
        total_time = time.time() - self.start_time
        logger.info(
            f"\n=== 处理完成 ==="
            f"\n总耗时: {total_time:.2f}秒"
            f"\n处理总数: {self.total_processed}"
            f"\n有效AdGuard规则: {len(self.valid_adguard)}"
            f"\n有效Hosts规则: {len(self.valid_hosts)}"
            f"\n输出文件:"
            f"\n  - {self.config.OUTPUT_ADGUARD}"
            f"\n  - {self.config.OUTPUT_HOSTS}"
        )

if __name__ == "__main__":
    try:
        processor = BlacklistProcessor()
        processor.process()
    except Exception as e:
        logger.critical(f"处理失败: {str(e)}", exc_info=True)
        sys.exit(1)