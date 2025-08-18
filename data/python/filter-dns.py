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
import dns.exception
from dns.message import make_query
from dns.rdatatype import A
import ssl
import socket

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# 环境变量配置（支持hosts原始语法输入）
class Config:
    INPUT_FILE = os.getenv("INPUT_FILE", "adblock.txt")  # 输入文件可能包含hosts语法
    OUTPUT_ADGUARD = os.getenv("OUTPUT_ADGUARD", "dns.txt")
    OUTPUT_HOSTS = os.getenv("OUTPUT_HOSTS", "hosts.txt")
    IS_CI = os.getenv("CI", "false").lower() == "true"
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", 4 if IS_CI else 8))
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", 5000 if IS_CI else 10000))
    # DNS验证配置
    DNS_SERVERS = os.getenv("DNS_SERVERS", "8.8.8.8,1.1.1.1").split(",")
    REQUIRE_CONSENSUS = int(os.getenv("REQUIRE_CONSENSUS", 1))
    DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", 2 if IS_CI else 5))
    DNS_RETRIES = int(os.getenv("DNS_RETRIES", 1 if IS_CI else 2))
    # 过滤配置（仅排除放行规则）
    EXCLUDE_PREFIXES = {"@@"}  # 排除AdGuard放行规则
    EXCLUDE_SUFFIXES = {".local", ".lan", ".localhost", ".internal"}
    # 允许的hosts拦截IP（标准拦截IP）
    ALLOWED_HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::1"}
    # WHOIS配置
    WHOIS_ENABLED = os.getenv("WHOIS_ENABLED", "false" if IS_CI else "true").lower() == "true"
    WHOIS_CACHE_TTL = 3600

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
        self.valid_adguard = set()  # 含AdGuard规则和未转换的hosts规则（保持原始格式）
        self.valid_hosts = set()    # 标准化hosts规则（IP+域名）
        self.total_processed = 0

    def _atomic_write(self, content, filepath):
        temp_path = f"{filepath}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(content)) + "\n")
        os.replace(temp_path, filepath)
        logger.info(f"已写入 {len(content)} 条规则到 {filepath}")

    def _parse_hosts_line(self, line):
        """解析hosts原始语法行：提取IP和域名列表（支持空格/制表符分隔、注释）"""
        # 移除行内注释（#后面的内容）
        line = re.sub(r"#.*$", "", line).strip()
        if not line:
            return None, []  # 空行
        
        # 用任意空白字符（空格/制表符）拆分，提取IP和域名列表
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            return None, []  # 不符合hosts格式（至少IP+1个域名）
        
        ip = parts[0]
        domains = parts[1:]  # 可能有多个域名（如0.0.0.0 a.com b.com）
        return ip, domains

    def _batch_reader(self):
        all_rules = set()
        try:
            with open(self.config.INPUT_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith(("#", "!")):  # 跳过纯注释行
                        continue
                    all_rules.add(line)
            logger.info(f"已加载规则文件: {self.config.INPUT_FILE}，去重后共 {len(all_rules)} 条规则")
        except FileNotFoundError:
            logger.error(f"核心规则文件 {self.config.INPUT_FILE} 不存在，无法继续处理")
            sys.exit(1)
        except Exception as e:
            logger.error(f"读取文件 {self.config.INPUT_FILE} 失败: {str(e)}")
            sys.exit(1)

        rules_list = list(all_rules)
        for i in range(0, len(rules_list), self.config.BATCH_SIZE):
            yield rules_list[i:i + self.config.BATCH_SIZE]

    @lru_cache(maxsize=10000)
    def _is_domain_expired(self, domain):
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
                expired = True
            else:
                if isinstance(expiration, list):
                    expiration = expiration[0]
                expired = expiration < now
        except Exception as e:
            logger.debug(f"WHOIS查询 {domain} 失败: {str(e)}")
            expired = False
        
        with self._cache_lock:
            self._whois_cache[domain] = (time.time(), expired)
        return expired

    def _extract_core_domain(self, rule):
        """增强版解析：兼容hosts语法和AdGuard语法"""
        # 先尝试解析是否为hosts规则
        ip, domains = self._parse_hosts_line(rule)
        if ip and domains:
            # 对于hosts规则，返回第一个有效域名（用于验证）和原始规则
            return (domains[0], rule) if domains else (None, rule)
        
        # AdGuard基础规则（带修饰符$）
        base_with_modifier = re.match(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)", rule)
        if base_with_modifier:
            return base_with_modifier.group(1), rule
        
        # AdGuard无||前缀但带$修饰符
        domain_with_modifier = re.match(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\$", rule)
        if domain_with_modifier:
            return domain_with_modifier.group(1), rule
        
        # 通配符规则（含修饰符）
        wildcard_with_mod = re.match(r"^\*\.(.+?\.[a-zA-Z]{2,})(\^|\$|$)", rule)
        if wildcard_with_mod:
            return wildcard_with_mod.group(1), rule
        
        # 元素隐藏规则
        elem_hide_ext = re.match(r"^([a-zA-Z0-9.*-]+\.[a-zA-Z]{2,})#[@#]", rule)
        if elem_hide_ext:
            domain_part = elem_hide_ext.group(1).lstrip("*.").strip()
            return domain_part, rule
        
        # $domain参数规则
        domain_param = re.search(r"\$domain=([^,]+)", rule)
        if domain_param:
            domain = domain_param.group(1).lstrip("~")
            if "." in domain and len(domain.split(".")) >= 2:
                return domain, rule
        
        # 路径拦截规则
        path_rule = re.match(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/", rule)
        if path_rule:
            return path_rule.group(1), rule
        
        # 基础AdGuard规则（无修饰符）
        adg_base = re.match(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", rule)
        if adg_base:
            return adg_base.group(1), rule
        
        # 简单正则规则
        regex_rule = re.match(r"^/(.+?\.[a-zA-Z]{2,})/", rule)
        if regex_rule:
            return regex_rule.group(1), rule
        
        # 无法提取域名的特殊规则（保留原始规则）
        return None, rule

    def _is_valid_ip(self, ip):
        """验证IP是否为标准拦截IP（hosts规则专用）"""
        return ip in self.config.ALLOWED_HOSTS_IPS

    def _dns_query(self, server, domain):
        try:
            if server.startswith("https://"):
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
                host = server.split("://")[-1].split(":")[0]
                with socket.create_connection((host, 853)) as sock:
                    with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls_sock:
                        tls_sock.sendall(make_query(domain, A).to_wire())
                        return len(dns.message.from_wire(tls_sock.recv(1024)).answer) > 0
            else:
                self._udp_resolvers[server].resolve(domain, "A")
                return True
        except Exception:
            return False

    @retry(
        stop=stop_after_attempt(Config.DNS_RETRIES),
        wait=wait_exponential(multiplier=1, min=1, max=3)
    )
    def _is_domain_valid(self, domain):
        with self._cache_lock:
            if domain in self._valid_domains:
                return True
            if domain in self._invalid_domains:
                return False
        
        if not domain or any(domain.endswith(s) for s in self.config.EXCLUDE_SUFFIXES):
            with self._cache_lock:
                self._invalid_domains.add(domain)
            return False
        
        success_count = 0
        for server in self.config.DNS_SERVERS:
            if self._dns_query(server, domain):
                success_count += 1
                if success_count >= self.config.REQUIRE_CONSENSUS:
                    break
        
        is_valid = success_count >= self.config.REQUIRE_CONSENSUS
        with self._cache_lock:
            if is_valid:
                self._valid_domains.add(domain)
            else:
                self._invalid_domains.add(domain)
        return is_valid

    def _process_single_rule(self, rule):
        # 过滤AdGuard放行规则（@@开头）
        if any(rule.startswith(p) for p in self.config.EXCLUDE_PREFIXES):
            return None, None
        
        # 解析是否为hosts规则（单独处理多域名场景）
        ip, domains = self._parse_hosts_line(rule)
        if ip and domains:
            # 验证hosts规则的IP有效性
            if not self._is_valid_ip(ip):
                logger.debug(f"无效hosts IP（过滤）: {ip}（规则: {rule}）")
                return None, None
            
            # 验证所有域名（只要有一个有效，就保留整个hosts规则）
            valid_domains = []
            for domain in domains:
                clean_domain = domain.lstrip("*.").strip()
                if self._is_domain_valid(clean_domain) and not self._is_domain_expired(clean_domain):
                    valid_domains.append(domain)  # 保留原始域名格式（含*）
            
            if not valid_domains:
                logger.debug(f"hosts域名均无效（过滤）: {domains}（规则: {rule}）")
                return None, None
            
            # 保留原始hosts规则（含所有有效域名）到AdGuard输出（兼容原始格式）
            # 同时生成标准化hosts规则（每个域名一行，避免多域名）
            original_hosts_rule = f"{ip} {' '.join(valid_domains)}"
            standardized_hosts = [f"{ip} {d}" for d in valid_domains]
            return original_hosts_rule, standardized_hosts
        
        # 处理非hosts规则（AdGuard语法）
        domain, original_rule = self._extract_core_domain(rule)
        
        # 验证域名（若能提取）
        if domain:
            if not self._is_domain_valid(domain):
                logger.debug(f"域名无效（过滤）: {domain}（规则: {original_rule}）")
                return None, None
            if self._is_domain_expired(domain):
                logger.debug(f"域名已过期（过滤）: {domain}（规则: {original_rule}）")
                return None, None
        
        # 生成Hosts规则（仅对可转换的AdGuard规则）
        hosts_rule = None
        if domain and re.match(r"^\|\|.*|^\*\.", original_rule):
            clean_domain = domain.lstrip("*.").strip()
            hosts_rule = [f"0.0.0.0 {clean_domain}"]  # 用列表统一格式
        
        return original_rule, hosts_rule

    def process(self):
        start_time = time.time()
        logger.info(f"开始处理规则（含hosts语法），输入文件: {self.config.INPUT_FILE}，CI环境: {self.config.IS_CI}")
        logger.info(f"WHOIS验证状态: {'启用' if self.config.WHOIS_ENABLED else '禁用'}，DNS服务器: {self.config.DNS_SERVERS}")
        
        for batch in self._batch_reader():
            with ThreadPoolExecutor(max_workers=self.config.MAX_WORKERS) as executor:
                futures = {executor.submit(self._process_single_rule, rule): rule for rule in batch}
                for future in as_completed(futures):
                    adg_rule, hosts_rules = future.result()
                    if adg_rule:
                        self.valid_adguard.add(adg_rule)
                    if hosts_rules:  # hosts_rules可能是列表（多域名）
                        self.valid_hosts.update(hosts_rules)
                    self.total_processed += 1
                    if self.total_processed % 200 == 0:
                        rate = len(self.valid_adguard) / self.total_processed if self.total_processed > 0 else 0.0
                        logger.info(f"已处理 {self.total_processed} 条规则，有效率: {rate:.2%}")
        
        self._atomic_write(self.valid_adguard, self.config.OUTPUT_ADGUARD)
        self._atomic_write(self.valid_hosts, self.config.OUTPUT_HOSTS)
        
        elapsed = time.time() - start_time
        logger.info(f"处理完成！耗时: {elapsed:.2f}秒，有效AdGuard规则: {len(self.valid_adguard)}，有效Hosts规则: {len(self.valid_hosts)}")

if __name__ == "__main__":
    processor = BlacklistProcessor()
    processor.process()
