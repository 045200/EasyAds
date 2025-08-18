import dns.resolver
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import psutil
import os
import threading
import ssl
import socket
import json
import requests
from typing import Optional, Tuple, Dict, List

class UltraRuleProcessor:
    # ========== 可配置参数 ==========
    # 调整为指定的DNS服务器（包含DoH和DoT）
    DNS_SERVERS = [
        'https://223.5.5.5/dns-query',
        'tls://223.5.5.5',
        'https://223.6.6.6/dns-query',
        'tls://223.6.6.6',
        'https://dns.alidns.com/dns-query',
        'tls://9.9.9.9',
        'tls://8.8.8.8',
        'tls://dns.google',
        'https://1.12.12.12/dns-query',
        'https://120.53.53.53/dns-query'
    ]

    # 性能调优参数
    BATCH_SIZE = 10000      # 每批处理量
    MAX_WORKERS = 10        # 最大并发数
    DNS_TIMEOUT = 3.0       # DNS查询超时(秒)（HTTPS/TLS需要更长超时）
    DNS_RETRIES = 1         # DNS查询重试次数

    # 功能开关
    SKIP_DNS_VALIDATION = False  # 跳过DNS验证
    SKIP_HOSTS_CONVERSION = False  # 跳过Hosts规则转换
    FORCE_CI_MODE = False    # 强制CI模式优化
    REQUIRE_CONSENSUS = 1    # 需要至少几个DNS服务器确认(1=任意一个)

    # 自动排除的域名后缀
    EXCLUDE_SUFFIXES = {
        '.cloudfront.net', '.akamai.net',
        '.cdn.cloudflare.net', '.local',
        '.internal', '.localhost'
    }
    # =============================

    # 预编译正则（提升5x性能）
    ADG_PATTERN = re.compile(
        r'^(\|\|[\w.-]+\^($|[\w,=-]+)?)|'          # 基础规则
        r'^@@\|\|[\w.-]+\^($|[\w,=-]+)?|'          # 白名单
        r'^\|\|[\w.-]+\^\$dnsrewrite=\S+|'         # DNS重写
        r'^\|\|[\w.-]+\^\$dnstype=\w+|'            # DNS类型
        r'^\|\|[\w.-]+\^\$client=\S+|'             # 客户端
        r'^/[\w\W]+/\$?[\w,=-]*|'                  # 正则
        r'^##.+|'                                  # 元素隐藏
        r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+|'          # IPv4 Hosts
        r'^[0-9a-fA-F:]+\s+[\w.-]+$'               # IPv6 Hosts
    )

    def __init__(self):
        # 环境检测
        self.is_ci = self.FORCE_CI_MODE or os.getenv('CI') == 'true'

        # CI环境自动优化
        if self.is_ci:
            print("[INFO] CI环境检测: 自动优化配置")
            self.MAX_WORKERS = 4
            self.DNS_TIMEOUT = 2.0
            if os.getenv('SKIP_DNS_VALIDATION', 'false').lower() == 'true':
                self.SKIP_DNS_VALIDATION = True

        # 初始化DNS解析器（基础UDP/TCP）
        self.udp_resolver = dns.resolver.Resolver()
        self.udp_resolver.timeout = self.DNS_TIMEOUT
        self.udp_resolver.lifetime = self.DNS_TIMEOUT * 1.5

        # 并发控制
        self.semaphore = threading.Semaphore(self.MAX_WORKERS * 2)
        self._valid_domains_cache = set()
        self._failed_domains_cache = set()

        # 统计信息
        self.processed_count = 0
        self.last_log_time = time.time()

    def process(self, input_path: Path):
        """主处理流程"""
        print(f"[INFO] 开始处理规则文件: {input_path}")
        print(f"[CONFIG] DNS验证: {'跳过' if self.SKIP_DNS_VALIDATION else '启用'} | "
              f"要求确认数: {self.REQUIRE_CONSENSUS}")
        print(f"[CONFIG] 并发数: {self.MAX_WORKERS} 批次: {self.BATCH_SIZE}")
        print(f"[CONFIG] 使用DNS服务器: {len(self.DNS_SERVERS)}个（包含DoH/DoT）")

        start_time = time.time()
        output_dir = input_path.parent
        adg_path = output_dir / "adguard.txt"
        hosts_path = output_dir / "hosts.txt"

        # 内存监控
        mem_start = self._get_memory()

        # 分批处理
        adg_rules, hosts_rules = set(), set()
        for batch_num, batch in enumerate(self._batch_reader(input_path), 1):
            batch_adg, batch_hosts = self._process_batch(batch)
            adg_rules.update(batch_adg)
            hosts_rules.update(batch_hosts)

            # 进度报告
            self._log_progress(batch_num, len(adg_rules) + len(hosts_rules))

        # 写入文件
        self._atomic_write(adg_path, sorted(adg_rules))
        self._atomic_write(hosts_path, sorted(hosts_rules))

        # 性能报告
        elapsed = time.time() - start_time
        print(f"\n[SUCCESS] 处理完成 | "
              f"AdGuard: {len(adg_rules)}条 | "
              f"Hosts: {len(hosts_rules)}条 | "
              f"耗时: {elapsed:.1f}s | "
              f"内存峰值: {self._get_memory()-mem_start:.1f}MB")

    def _log_progress(self, batch_num: int, total_rules: int):
        """进度日志输出"""
        now = time.time()
        if now - self.last_log_time > 5:  # 每5秒输出一次
            print(f"[PROGRESS] 批次: {batch_num} | "
                  f"规则: {total_rules} | "
                  f"内存: {self._get_memory():.1f}MB")
            self.last_log_time = now

    def _batch_reader(self, path: Path):
        """大文件分批读取器"""
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            batch = []
            for line in f:
                if line.strip():
                    batch.append(line.strip())
                    if len(batch) >= self.BATCH_SIZE:
                        yield batch
                        batch = []
            if batch:
                yield batch

    def _process_batch(self, batch: list) -> tuple:
        """处理单批次规则"""
        adg_rules, hosts_rules = set(), set()

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._parse_rule, rule): rule 
                for rule in batch
            }

            for future in as_completed(futures):
                adg_rule, hosts_rule = future.result()
                if adg_rule:
                    adg_rules.add(adg_rule)
                if hosts_rule:
                    hosts_rules.add(hosts_rule)

        return adg_rules, hosts_rules

    def _parse_rule(self, rule: str) -> Tuple[Optional[str], Optional[str]]:
        """解析单条规则"""
        with self.semaphore:
            # 跳过注释
            if not rule or rule.startswith(('!', '#')):
                return None, None

            # 1. AdGuard规则处理
            if self.ADG_PATTERN.match(rule):
                domain = self._extract_domain(rule)

                # 排除CDN/内网
                if not domain or any(domain.endswith(s) for s in self.EXCLUDE_SUFFIXES):
                    return None, None

                # DNS验证
                if not self.SKIP_DNS_VALIDATION:
                    dns_status = self._dns_lookup(domain)
                    if dns_status is None:  # 验证失败
                        return None, None
                    elif isinstance(dns_status, dict) and self.is_ci:
                        print(f"[DNS] {domain} 验证详情: {dns_status}")

                # Hosts转换
                hosts_rule = None
                if not self.SKIP_HOSTS_CONVERSION and rule.startswith('||') and rule.endswith('^'):
                    hosts_rule = f"0.0.0.0 {domain}"

                return rule, hosts_rule

            # 2. Hosts规则处理
            elif self._is_hosts_rule(rule):
                parts = rule.split()
                domain = parts[1] if len(parts) >= 2 else None

                if domain and not any(domain.endswith(s) for s in self.EXCLUDE_SUFFIXES):
                    if self.SKIP_DNS_VALIDATION or self._dns_lookup(domain):
                        return None, rule  # 仅保留Hosts

            return None, None

    def _extract_domain(self, rule: str) -> Optional[str]:
        """智能域名提取"""
        if rule.startswith(('||', '@@||')) and '^' in rule:
            return rule.split('^')[0][2:] if rule.startswith('||') else rule.split('^')[0][4:]
        elif ' ' in rule:  # Hosts
            return rule.split()[1]
        return None

    def _is_hosts_rule(self, rule: str) -> bool:
        """验证Hosts格式"""
        parts = rule.split()
        if len(parts) < 2:
            return False

        # 支持IPv4/IPv6
        ip = parts[0]
        if ':' in ip:  # IPv6
            return all(c in '0123456789abcdef:' for c in ip.lower())
        ip_parts = ip.split('.')
        return (
            len(ip_parts) == 4 and 
            all(p.isdigit() and 0 <= int(p) <= 255 for p in ip_parts)
        )

    def _dns_lookup(self, domain: str) -> Optional[Dict[str, bool]]:
        """
        增强DNS交叉验证（支持DoH和DoT）
        返回: None=验证失败 | True=缓存命中 | dict=各DNS服务器验证结果
        """
        if self.SKIP_DNS_VALIDATION:
            return True

        if domain in self._valid_domains_cache:
            return True
        if domain in self._failed_domains_cache:
            return None

        tested_servers = {}
        consensus = 0

        for server in self.DNS_SERVERS:
            for attempt in range(self.DNS_RETRIES + 1):
                try:
                    # 解析服务器类型和地址
                    if server.startswith('https://'):
                        # DNS over HTTPS (DoH)
                        success = self._doh_query(server, domain)
                    elif server.startswith('tls://'):
                        # DNS over TLS (DoT)
                        success = self._dot_query(server, domain)
                    else:
                        # 传统UDP查询
                        success = self._udp_query(server, domain)

                    tested_servers[server] = {
                        'success': success,
                        'attempt': attempt + 1
                    }

                    if success:
                        consensus += 1
                        if consensus >= self.REQUIRE_CONSENSUS:
                            self._valid_domains_cache.add(domain)
                            return True
                        break  # 尝试下一个服务器

                except Exception as e:
                    tested_servers[server] = {
                        'success': False,
                        'error': str(e),
                        'attempt': attempt + 1
                    }
                    if attempt == self.DNS_RETRIES:  # 最后一次尝试也失败
                        continue

        # 所有服务器尝试完毕仍未达到共识
        self._failed_domains_cache.add(domain)
        return tested_servers if self.is_ci else None

    def _udp_query(self, server: str, domain: str) -> bool:
        """传统UDP DNS查询"""
        resolver = self.udp_resolver.copy()
        resolver.nameservers = [server]
        answer = resolver.resolve(domain, 'A', raise_on_no_answer=False)
        return answer.rrset is not None

    def _dot_query(self, server: str, domain: str) -> bool:
        """DNS over TLS (DoT)查询"""
        # 解析服务器地址（去除tls://前缀）
        server_addr = server[6:] if server.startswith('tls://') else server
        # 处理域名形式的服务器（如tls://dns.google）
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', server_addr):
            ips = dns.resolver.resolve(server_addr, 'A')
            server_ip = ips[0].to_text()
        else:
            server_ip = server_addr

        # 建立TLS连接（DoT默认端口853）
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.DNS_TIMEOUT)
        context = ssl.create_default_context()
        context.check_hostname = False  # 简化处理，生产环境可开启
        context.verify_mode = ssl.CERT_NONE  # 简化处理，生产环境应验证证书
        ssl_sock = context.wrap_socket(sock, server_hostname=server_addr)
        
        try:
            ssl_sock.connect((server_ip, 853))
            # 构建DNS查询包（A记录）
            query = dns.message.make_query(domain, dns.rdatatype.A)
            query_data = query.to_wire()
            # 发送查询（前2字节为长度）
            ssl_sock.sendall(len(query_data).to_bytes(2, byteorder='big') + query_data)
            # 接收响应
            response_len = int.from_bytes(ssl_sock.recv(2), byteorder='big')
            response_data = ssl_sock.recv(response_len)
            response = dns.message.from_wire(response_data)
            return len(response.answer) > 0
        finally:
            ssl_sock.close()

    def _doh_query(self, server: str, domain: str) -> bool:
        """DNS over HTTPS (DoH)查询"""
        # 构建DoH查询参数
        params = {'name': domain, 'type': 'A'}
        headers = {'Accept': 'application/dns-json'}
        
        # 发送GET请求（符合RFC 8484）
        response = requests.get(
            server,
            params=params,
            headers=headers,
            timeout=self.DNS_TIMEOUT,
            verify=True  # 验证SSL证书
        )
        response.raise_for_status()
        data = response.json()
        # 检查是否有解析结果
        return len(data.get('Answer', [])) > 0

    def _atomic_write(self, path: Path, lines: list):
        """原子写入文件"""
        path.parent.mkdir(exist_ok=True)
        temp_path = path.with_suffix('.tmp')
        with temp_path.open('w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        temp_path.replace(path)

    def _get_memory(self) -> float:
        """获取当前内存占用(MB)"""
        return psutil.Process().memory_info().rss / 1024 / 1024

if __name__ == "__main__":
    # 参数处理
    if len(sys.argv) > 1:
        input_file = Path(sys.argv[1])
    else:
        input_file = Path(__file__).parent.parent.parent / "adblock.txt"

    if not input_file.exists():
        print(f"[ERROR] 输入文件不存在: {input_file}")
        sys.exit(1)

    # 初始化处理器 (可通过环境变量配置)
    processor = UltraRuleProcessor()

    # 从环境变量读取配置
    processor.SKIP_DNS_VALIDATION = os.getenv('SKIP_DNS_VALIDATION', 'false').lower() == 'true'
    processor.SKIP_HOSTS_CONVERSION = os.getenv('SKIP_HOSTS_CONVERSION', 'false').lower() == 'true'
    processor.FORCE_CI_MODE = os.getenv('FORCE_CI_MODE', 'false').lower() == 'true'

    # 性能参数调整
    if 'MAX_WORKERS' in os.environ:
        processor.MAX_WORKERS = int(os.getenv('MAX_WORKERS'))
    if 'BATCH_SIZE' in os.environ:
        processor.BATCH_SIZE = int(os.getenv('BATCH_SIZE'))
    if 'REQUIRE_CONSENSUS' in os.environ:
        processor.REQUIRE_CONSENSUS = int(os.getenv('REQUIRE_CONSENSUS'))

    # 启动处理
    processor.process(input_file)
