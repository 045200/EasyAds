#!/usr/bin/env python3
"""
高效黑名单处理器 - 支持AdGuard和Hosts格式规则验证与转换
路径修复版本：确保输入输出文件在根目录，脚本可在子目录运行
"""

import os
import re
import sys
import time
import base64
import whois
import logging
import threading
from functools import lru_cache
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_exponential
import requests
import dns.resolver
import dns.message
import dns.rdatatype
import ssl
import socket
from typing import Tuple, List, Set, Optional, Dict

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class Config:
    """配置类（环境变量优先）"""
    # 类级别的基础配置，确保装饰器可以访问
    IS_CI = os.getenv("CI", "false").lower() == "true"
    DNS_RETRIES = int(os.getenv("DNS_RETRIES", 1 if IS_CI else 2))  # 类属性，供装饰器使用
    
    def __init__(self):
        # 根目录路径（脚本可能位于子目录如/data/python/）
        self.ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

        # 输入输出配置（确保路径在根目录）
        self.INPUT_FILE = self._get_abs_path(os.getenv("INPUT_FILE", "adblock.txt"))
        self.OUTPUT_ADGUARD = self._get_abs_path(os.getenv("OUTPUT_ADGUARD", "dns.txt"))
        self.OUTPUT_HOSTS = self._get_abs_path(os.getenv("OUTPUT_HOSTS", "hosts.txt"))

        # 性能配置
        self.MAX_WORKERS = int(os.getenv("MAX_WORKERS", 4 if self.IS_CI else 8))
        self.BATCH_SIZE = int(os.getenv("BATCH_SIZE", 5000 if self.IS_CI else 10000))

        # DNS验证配置
        self.DNS_SERVERS = os.getenv("DNS_SERVERS", "8.8.8.8,1.1.1.1").split(",")
        self.REQUIRE_CONSENSUS = int(os.getenv("REQUIRE_CONSENSUS", 1))
        self.DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", 2 if self.IS_CI else 5))
        
        # 过滤配置
        self.EXCLUDE_PREFIXES = {"@@"}  # AdGuard放行规则
        self.EXCLUDE_SUFFIXES = {".local", ".lan", ".localhost", ".internal"}
        self.ALLOWED_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::1"}

        # WHOIS配置
        self.WHOIS_ENABLED = os.getenv("WHOIS_ENABLED", "false" if self.IS_CI else "true").lower() == "true"
        self.WHOIS_CACHE_TTL = 3600  # 1小时缓存

    def _get_abs_path(self, filename: str) -> str:
        """将相对路径转换为根目录绝对路径"""
        if os.path.isabs(filename):
            return filename
        return os.path.join(self.ROOT_DIR, filename)

class BlacklistProcessor:
    """黑名单处理核心类"""

    # 预编译所有正则表达式（性能关键）
    REGEX_PATTERNS = {
        'hosts_comment': re.compile(r"#.*$"),
        'hosts_split': re.compile(r"\s+"),
        'adg_base_mod': re.compile(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)"),
        'adg_domain_mod': re.compile(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\$"),
        'wildcard_mod': re.compile(r"^\*\.(.+?\.[a-zA-Z]{2,})(\^|\$|$)"),
        'elem_hide': re.compile(r"^([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})#[@#]"),
        'domain_param': re.compile(r"\$domain=([^,]+)"),
        'path_rule': re.compile(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/"),
        'adg_base': re.compile(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$"),
        'regex_rule': re.compile(r"^/(.+?\.[a-zA-Z]{2,})/"),
    }

    def __init__(self):
        self.config = Config()
        self._init_resolvers()

        # 线程安全存储
        self._valid_domains: Set[str] = set()
        self._invalid_domains: Set[str] = set()
        self._whois_cache: Dict[str, Tuple[float, bool]] = {}
        self._cache_lock = threading.Lock()

        # 结果存储
        self.valid_adguard: Set[str] = set()
        self.valid_hosts: Set[str] = set()
        self.total_processed = 0
        self.start_time = time.time()

    def _init_resolvers(self):
        """初始化DNS解析器（按协议分类）"""
        self._resolvers = {
            'doh': [s for s in self.config.DNS_SERVERS if s.startswith("https://")],
            'dot': [s for s in self.config.DNS_SERVERS if s.startswith("tls://")],
            'udp': [s for s in self.config.DNS_SERVERS if not s.startswith(("https://", "tls://"))]
        }

        # 初始化UDP解析器
        self._udp_resolvers = {}
        for server in self._resolvers['udp']:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = self.config.DNS_TIMEOUT
            resolver.lifetime = self.config.DNS_TIMEOUT * self.config.DNS_RETRIES
            self._udp_resolvers[server] = resolver

    def _atomic_write(self, content: Set[str], filepath: str):
        """原子写入文件"""
        # 确保输出目录存在
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        temp_path = f"{filepath}.tmp"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(content)) + "\n")
            os.replace(temp_path, filepath)
            logger.info(f"写入 {len(content)} 条规则到 {filepath}")
        except Exception as e:
            logger.error(f"写入文件 {filepath} 失败: {str(e)}")
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def _batch_reader(self):
        """生成器：分批读取输入文件"""
        try:
            with open(self.config.INPUT_FILE, "r", encoding="utf-8") as f:
                batch = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(("#", "!")):
                        continue
                    batch.append(line)
                    if len(batch) >= self.config.BATCH_SIZE:
                        yield batch
                        batch = []
                if batch:
                    yield batch
        except FileNotFoundError:
            logger.error(f"输入文件 {self.config.INPUT_FILE} 不存在")
            sys.exit(1)
        except Exception as e:
            logger.error(f"读取文件失败: {str(e)}")
            sys.exit(1)

    def _parse_hosts_line(self, line: str) -> Tuple[Optional[str], List[str]]:
        """解析hosts行：返回(IP, 域名列表)"""
        line = self.REGEX_PATTERNS['hosts_comment'].sub("", line).strip()
        if not line:
            return None, []

        parts = self.REGEX_PATTERNS['hosts_split'].split(line)
        return (parts[0], parts[1:]) if len(parts) >= 2 else (None, [])

    @lru_cache(maxsize=10000)
    def _is_domain_expired(self, domain: str) -> bool:
        """检查域名是否过期（带缓存）"""
        if not self.config.WHOIS_ENABLED:
            return False

        now = datetime.now(timezone.utc)
        with self._cache_lock:
            if domain in self._whois_cache:
                cached_time, expired = self._whois_cache[domain]
                if time.time() - cached_time < self.config.WHOIS_CACHE_TTL:
                    return expired

        try:
            @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=1, min=1, max=3))
            def _query():
                return whois.whois(domain)

            w = _query()
            expiration = w.expiration_date if hasattr(w, 'expiration_date') else None
            if not expiration:
                expired = True
            else:
                expiration = expiration[0] if isinstance(expiration, list) else expiration
                expired = expiration < now if expiration else True
        except Exception as e:
            logger.debug(f"WHOIS查询失败: {domain} - {str(e)}")
            expired = False

        with self._cache_lock:
            self._whois_cache[domain] = (time.time(), expired)
        return expired

    def _extract_core_domain(self, rule: str) -> Tuple[Optional[str], str]:
        """从规则中提取核心域名（支持所有语法）"""
        # 1. 尝试解析为hosts规则
        ip, domains = self._parse_hosts_line(rule)
        if ip and domains:
            return domains[0], rule

        # 2. 按优先级尝试匹配AdGuard各种语法
        for pattern_name in [
            'adg_base_mod', 'adg_domain_mod', 'wildcard_mod',
            'elem_hide', 'domain_param', 'path_rule', 'adg_base', 'regex_rule'
        ]:
            match = self.REGEX_PATTERNS[pattern_name].match(rule)
            if match:
                return match.group(1).lstrip("*."), rule

        return None, rule

    def _dns_over_https(self, server: str, domain: str) -> bool:
        """DNS-over-HTTPS查询"""
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            b64_data = base64.urlsafe_b64encode(query.to_wire()).decode().rstrip("=")
            resp = requests.get(
                f"{server}?dns={b64_data}",
                headers={"Accept": "application/dns-message"},
                timeout=self.config.DNS_TIMEOUT,
                verify=True
            )
            resp.raise_for_status()
            return len(dns.message.from_wire(resp.content).answer) > 0
        except Exception:
            return False

    def _dns_over_tls(self, server: str, domain: str) -> bool:
        """DNS-over-TLS查询"""
        try:
            host = server.split("://")[-1].split(":")[0]
            with socket.create_connection((host, 853), timeout=self.config.DNS_TIMEOUT) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    tls_sock.sendall(dns.message.make_query(domain, dns.rdatatype.A).to_wire())
                    return len(dns.message.from_wire(tls_sock.recv(1024)).answer) > 0
        except Exception:
            return False

    def _dns_over_udp(self, server: str, domain: str) -> bool:
        """传统UDP DNS查询"""
        try:
            self._udp_resolvers[server].resolve(domain, "A")
            return True
        except Exception:
            return False

    @retry(stop=stop_after_attempt(Config.DNS_RETRIES), wait=wait_exponential(multiplier=1, min=1, max=3))
    def _is_domain_valid(self, domain: str) -> bool:
        """验证域名有效性（多协议DNS查询）"""
        if not domain or any(domain.endswith(s) for s in self.config.EXCLUDE_SUFFIXES):
            return False

        with self._cache_lock:
            if domain in self._valid_domains:
                return True
            if domain in self._invalid_domains:
                return False

        success_count = 0
        required = self.config.REQUIRE_CONSENSUS

        # 按协议类型并行查询
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for proto, servers in self._resolvers.items():
                if not servers:
                    continue
                server = servers[0]  # 每类协议只查一个服务器
                if proto == 'doh':
                    futures.append(executor.submit(self._dns_over_https, server, domain))
                elif proto == 'dot':
                    futures.append(executor.submit(self._dns_over_tls, server, domain))
                else:
                    futures.append(executor.submit(self._dns_over_udp, server, domain))

            for future in as_completed(futures):
                if future.result():
                    success_count += 1
                    if success_count >= required:
                        break

        is_valid = success_count >= required
        with self._cache_lock:
            if is_valid:
                self._valid_domains.add(domain)
            else:
                self._invalid_domains.add(domain)
        return is_valid

    def _process_single_rule(self, rule: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """处理单条规则（核心逻辑）"""
        # 排除放行规则
        if any(rule.startswith(p) for p in self.config.EXCLUDE_PREFIXES):
            return None, None

        # 处理hosts规则
        ip, domains = self._parse_hosts_line(rule)
        if ip and domains:
            if ip not in self.config.ALLOWED_HOSTS_IPS:
                return None, None

            valid_domains = []
            for domain in domains:
                clean_domain = domain.lstrip("*.").strip()
                if self._is_domain_valid(clean_domain) and not self._is_domain_expired(clean_domain):
                    valid_domains.append(domain)

            if not valid_domains:
                return None, None

            return f"{ip} {' '.join(valid_domains)}", [f"{ip} {d}" for d in valid_domains]

        # 处理AdGuard规则
        domain, original_rule = self._extract_core_domain(rule)
        if domain:
            if not self._is_domain_valid(domain) or self._is_domain_expired(domain):
                return None, None

        # 生成Hosts规则
        hosts_rule = None
        if domain and (rule.startswith("||") or rule.startswith("*.")):
            hosts_rule = [f"0.0.0.0 {domain.lstrip('*.')}"]

        return original_rule, hosts_rule

    def _log_progress(self):
        """记录处理进度"""
        elapsed = time.time() - self.start_time
        rate = self.total_processed / elapsed if elapsed > 0 else 0
        logger.info(
            f"已处理 {self.total_processed} 条 | "
            f"有效AdGuard: {len(self.valid_adguard)} | "
            f"有效Hosts: {len(self.valid_hosts)} | "
            f"速度: {rate:.1f} 条/秒"
        )

    def process(self):
        """主处理流程"""
        logger.info(f"开始处理规则文件: {self.config.INPUT_FILE}")
        logger.info(f"输出位置 - AdGuard: {self.config.OUTPUT_ADGUARD} | Hosts: {self.config.OUTPUT_HOSTS}")
        logger.info(f"DNS服务器: {self.config.DNS_SERVERS} | WHOIS: {'启用' if self.config.WHOIS_ENABLED else '禁用'}")

        for batch in self._batch_reader():
            with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
                futures = {executor.submit(self._process_single_rule, rule): rule for rule in batch}
                for future in as_completed(futures):
                    adg_rule, hosts_rules = future.result()
                    if adg_rule:
                        self.valid_adguard.add(adg_rule)
                    if hosts_rules:
                        self.valid_hosts.update(hosts_rules)
                    self.total_processed += 1

                    if self.total_processed % 500 == 0:
                        self._log_progress()

        # 最终写入
        self._atomic_write(self.valid_adguard, self.config.OUTPUT_ADGUARD)
        self._atomic_write(self.valid_hosts, self.config.OUTPUT_HOSTS)

        # 最终报告
        total_time = time.time() - self.start_time
        logger.info(
            f"处理完成！耗时: {total_time:.2f}秒 | "
            f"总处理: {self.total_processed} | "
            f"AdGuard规则: {len(self.valid_adguard)} | "
            f"Hosts规则: {len(self.valid_hosts)}"
        )

if __name__ == "__main__":
    processor = BlacklistProcessor()
    processor.process()
