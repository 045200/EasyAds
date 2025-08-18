import os
import re
import sys
import time
import json
import base64
import whois
import logging
import threading
from functools import lru_cache
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import requests
import dns.resolver
import dns.exception
from dns.message import make_query
from dns.rdatatype import A
import ssl
import socket

# 配置日志（适配GitHub CI）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# 环境变量配置（支持CI动态调整）
class Config:
    INPUT_FILE = os.getenv("INPUT_FILE", "adblock.txt")
    OUTPUT_ADGUARD = os.getenv("OUTPUT_ADGUARD", "dns.txt")
    OUTPUT_HOSTS = os.getenv("OUTPUT_HOSTS", "hosts.txt")
    # 环境与并发控制
    IS_CI = os.getenv("CI", "false").lower() == "true"
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", 4 if IS_CI else 8))
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", 5000 if IS_CI else 10000))
    # DNS验证配置
    DNS_SERVERS = os.getenv("DNS_SERVERS", "https://1.1.1.1/dns-query,https://8.8.8.8/dns-query,8.8.8.8,1.1.1.1").split(",")
    REQUIRE_CONSENSUS = int(os.getenv("REQUIRE_CONSENSUS", 1))
    DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", 3 if IS_CI else 5))
    DNS_RETRIES = int(os.getenv("DNS_RETRIES", 2))
    # 过滤配置（黑名单专属）
    EXCLUDE_PREFIXES = {"@@"}  # 移除例外规则
    EXCLUDE_SUFFIXES = {".local", ".lan", ".localhost", ".internal"}
    # WHOIS配置
    WHOIS_ENABLED = os.getenv("WHOIS_ENABLED", "true").lower() == "true"
    WHOIS_CACHE_TTL = 3600  # 1小时缓存

class BlacklistProcessor:
    def __init__(self):
        self.config = Config()
        # 线程安全缓存
        self._valid_domains = set()
        self._invalid_domains = set()
        self._whois_cache = {}
        self._cache_lock = threading.Lock()
        # DNS解析器初始化（UDP）
        self._udp_resolvers = {
            server: dns.resolver.Resolver() for server in self.config.DNS_SERVERS
            if not server.startswith(("https://", "tls://"))
        }
        for server, resolver in self._udp_resolvers.items():
            resolver.nameservers = [server]
            resolver.timeout = self.config.DNS_TIMEOUT
            resolver.lifetime = self.config.DNS_TIMEOUT * self.config.DNS_RETRIES
        # 结果存储
        self.valid_adguard = set()  # AdGuard黑名单规则
        self.valid_hosts = set()    # Hosts规则
        self.total_processed = 0

    def _atomic_write(self, content, filepath):
        """原子写入避免CI中断损坏文件"""
        temp_path = f"{filepath}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(content)) + "\n")
        os.replace(temp_path, filepath)
        logger.info(f"已写入 {len(content)} 条规则到 {filepath}")

    def _batch_reader(self):
        """分批读取规则（降低内存占用）"""
        try:
            with open(self.config.INPUT_FILE, "r", encoding="utf-8") as f:
                batch = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith(("#", "!")):  # 跳过注释和空行
                        batch.append(line)
                        if len(batch) >= self.config.BATCH_SIZE:
                            yield batch
                            batch = []
                if batch:
                    yield batch
        except FileNotFoundError:
            logger.error(f"输入文件 {self.config.INPUT_FILE} 不存在")
            sys.exit(1)

    @lru_cache(maxsize=10000)
    def _is_domain_expired(self, domain):
        """WHOIS检测域名过期（带缓存）"""
        if not self.config.WHOIS_ENABLED:
            return False
        
        now = datetime.now(timezone.utc)
        with self._cache_lock:
            if domain in self._whois_cache:
                cached_time, expired = self._whois_cache[domain]
                if time.time() - cached_time < self.config.WHOIS_CACHE_TTL:
                    return expired
        
        try:
            @retry(
                stop=stop_after_attempt(2),
                wait=wait_exponential(multiplier=1, min=1, max=3)
            )
            def _query():
                return whois.whois(domain)
            
            w = _query()
            expiration = w.get("expiration_date")
            if not expiration:
                expired = True  # 无过期时间视为无效
            else:
                if isinstance(expiration, list):
                    expiration = expiration[0]
                expired = expiration < now
        except Exception as e:
            logger.debug(f"WHOIS查询 {domain} 失败: {str(e)}")
            expired = True  # 查询失败默认视为过期
        
        with self._cache_lock:
            self._whois_cache[domain] = (time.time(), expired)
        return expired

    def _extract_core_domain(self, rule):
        """从黑名单规则中提取核心域名（用于验证）"""
        # 1. AdGuard基础规则（||example.com^ 或 ||example.com）
        adg_base = re.match(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|$)", rule)
        if adg_base:
            return adg_base.group(1), rule
        
        # 2. 通配符规则（*.example.com 或 *.sub.example.com）
        wildcard = re.match(r"^\*\.(.+?\.[a-zA-Z]{2,})$", rule)
        if wildcard:
            return wildcard.group(1), rule  # 提取 example.com
        
        # 3. 元素隐藏规则（example.com##.ad 或 *.example.com##.ad）
        elem_hide = re.match(r"^([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})##", rule)
        if elem_hide:
            domain_part = elem_hide.group(1).lstrip("*.").strip()  # 移除前缀*
            return domain_part, rule
        
        # 4. 重定向规则（||example.com^$dnsrewrite=...）
        dns_rewrite = re.match(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\^?\$dnsrewrite", rule)
        if dns_rewrite:
            return dns_rewrite.group(1), rule
        
        # 5. Hosts规则（0.0.0.0 example.com 或 127.0.0.1 *.example.com）
        hosts_rule = re.match(r"^\d+\.\d+\.\d+\.\d+\s+([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})$", rule)
        if hosts_rule:
            domain_part = hosts_rule.group(1).lstrip("*.").strip()
            return domain_part, rule
        
        # 6. 正则规则（/example\.com/ 简化提取）
        regex_rule = re.match(r"^/(.+?\.[a-zA-Z]{2,})/", rule)
        if regex_rule:
            return regex_rule.group(1), rule
        
        return None, None  # 无法提取域名的规则（如特殊修饰符）

    def _is_valid_ip(self, ip):
        """验证IP格式是否有效（用于Hosts规则）"""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except:
            return False

    def _dns_query(self, server, domain):
        """多协议DNS查询（DoH/DoT/UDP）"""
        try:
            if server.startswith("https://"):
                # DoH查询（RFC 8484标准）
                query = make_query(domain, A)
                b64_data = base64.urlsafe_b64encode(query.to_wire()).decode().rstrip("=")
                resp = requests.get(
                    f"{server}?dns={b64_data}",
                    headers={"Accept": "application/dns-message"},
                    timeout=self.config.DNS_TIMEOUT,
                    verify=True
                )
                resp.raise_for_status()
                return len(dns.message.from_wire(resp.content).answer) > 0
            elif server.startswith("tls://"):
                # DoT查询
                host = server.split("://")[-1].split(":")[0]
                with socket.create_connection((host, 853)) as sock:
                    with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls_sock:
                        tls_sock.sendall(make_query(domain, A).to_wire())
                        return len(dns.message.from_wire(tls_sock.recv(1024)).answer) > 0
            else:
                # UDP查询（修复DeprecationWarning：使用resolve替代query）
                self._udp_resolvers[server].resolve(domain, "A")
                return True
        except Exception:
            return False

    @retry(
        stop=stop_after_attempt(Config.DNS_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=3)
    )
    def _is_domain_valid(self, domain):
        """验证域名是否有效（DNS+黑名单过滤）"""
        # 缓存检查
        with self._cache_lock:
            if domain in self._valid_domains:
                return True
            if domain in self._invalid_domains:
                return False
        
        # 过滤特殊后缀和空域名
        if not domain or any(domain.endswith(s) for s in self.config.EXCLUDE_SUFFIXES):
            with self._cache_lock:
                self._invalid_domains.add(domain)
            return False
        
        # 多服务器共识验证
        success_count = 0
        for server in self.config.DNS_SERVERS:
            if self._dns_query(server, domain):
                success_count += 1
                if success_count >= self.config.REQUIRE_CONSENSUS:
                    break  # 提前退出
        
        is_valid = success_count >= self.config.REQUIRE_CONSENSUS
        with self._cache_lock:
            if is_valid:
                self._valid_domains.add(domain)
            else:
                self._invalid_domains.add(domain)
        return is_valid

    def _process_single_rule(self, rule):
        """处理单条规则（仅保留黑名单）"""
        # 移除例外规则（@@开头）
        if any(rule.startswith(p) for p in self.config.EXCLUDE_PREFIXES):
            return None, None
        
        # 提取域名和原始规则
        domain, original_rule = self._extract_core_domain(rule)
        if not domain:
            # 无法提取域名的规则（如特殊修饰符）直接保留（非DNS依赖）
            return original_rule, None
        
        # 验证域名有效性（DNS+WHOIS）
        if not self._is_domain_valid(domain):
            logger.debug(f"域名无效: {domain}（规则: {original_rule}）")
            return None, None
        if self._is_domain_expired(domain):
            logger.debug(f"域名已过期: {domain}（规则: {original_rule}）")
            return None, None
        
        # 生成Hosts规则（仅对基础/通配符规则转换）
        hosts_rule = None
        if re.match(r"^\|\|.*|^\*\.|^\d+\.\d+\.\d+\.\d+\s+", original_rule):
            clean_domain = domain.lstrip("*.").strip()
            hosts_rule = f"0.0.0.0 {clean_domain}"
        
        return original_rule, hosts_rule

    def process(self):
        """主处理流程"""
        start_time = time.time()
        logger.info(f"开始处理纯黑名单规则，输入: {self.config.INPUT_FILE}，CI环境: {self.config.IS_CI}")
        
        # 分批处理规则
        for batch in self._batch_reader():
            with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
                futures = {executor.submit(self._process_single_rule, rule): rule for rule in batch}
                for future in as_completed(futures):
                    adg_rule, hosts_rule = future.result()
                    if adg_rule:
                        self.valid_adguard.add(adg_rule)
                    if hosts_rule:
                        self.valid_hosts.add(hosts_rule)
                    self.total_processed += 1
                    if self.total_processed % 200 == 0:
                        logger.info(f"已处理 {self.total_processed} 条规则，有效率: {len(self.valid_adguard)/self.total_processed:.2%}")
        
        # 写入结果
        self._atomic_write(self.valid_adguard, self.config.OUTPUT_ADGUARD)
        self._atomic_write(self.valid_hosts, self.config.OUTPUT_HOSTS)
        
        # 输出统计
        elapsed = time.time() - start_time
        logger.info(f"处理完成！耗时: {elapsed:.2f}秒，有效AdGuard规则: {len(self.valid_adguard)}，有效Hosts规则: {len(self.valid_hosts)}")

if __name__ == "__main__":
    processor = BlacklistProcessor()
    processor.process()
