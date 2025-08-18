#!/usr/bin/env python3
"""
AdGuard Home 规则专业处理器 - 增强CI兼容版
功能：合并、去重、验证、分类输出AdGuard和Hosts规则
"""

import dns.resolver
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import psutil
import os
import threading
from typing import Optional, Tuple

class UltraRuleProcessor:
    # ========== 可配置参数 ==========
    # DNS服务器配置（国内外混合）
    DNS_SERVERS = [
        '1.1.1.1',      # Cloudflare
        '8.8.8.8',      # Google
        '223.5.5.5',    # 阿里
        '119.29.29.29'  # DNSPod
    ]
    
    # 性能调优参数
    BATCH_SIZE = 10000      # 每批处理量
    MAX_WORKERS = 10        # 最大并发数
    DNS_TIMEOUT = 1.5       # DNS查询超时(秒)
    
    # 功能开关
    SKIP_DNS_VALIDATION = False  # 跳过DNS验证
    SKIP_HOSTS_CONVERSION = False  # 跳过Hosts规则转换
    FORCE_CI_MODE = True    # 强制CI模式优化
    
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
            self.DNS_TIMEOUT = 0.5
            if os.getenv('SKIP_DNS_VALIDATION', 'false').lower() == 'true':
                self.SKIP_DNS_VALIDATION = True
        
        # 初始化DNS解析器
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.DNS_TIMEOUT
        self.resolver.lifetime = self.DNS_TIMEOUT * 1.5
        self.resolver.nameservers = self.DNS_SERVERS
        
        # 并发控制
        self.semaphore = threading.Semaphore(self.MAX_WORKERS * 2)
        self._valid_domains_cache = set()
        
        # 统计信息
        self.processed_count = 0
        self.last_log_time = time.time()

    def process(self, input_path: Path):
        """主处理流程"""
        print(f"[INFO] 开始处理规则文件: {input_path}")
        print(f"[CONFIG] DNS验证: {'跳过' if self.SKIP_DNS_VALIDATION else '启用'}")
        print(f"[CONFIG] 并发数: {self.MAX_WORKERS} 批次: {self.BATCH_SIZE}")
        
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
                if not self.SKIP_DNS_VALIDATION and not self._dns_lookup(domain):
                    return None, None

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

    def _dns_lookup(self, domain: str) -> bool:
        """增强DNS验证"""
        if self.SKIP_DNS_VALIDATION:
            return True
            
        if domain in self._valid_domains_cache:
            return True

        try:
            # 快速失败模式
            answer = self.resolver.resolve(domain, 'A', raise_on_no_answer=False)
            if answer.rrset is not None:
                self._valid_domains_cache.add(domain)
                return True
            return False
        except:
            return False

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
    
    # 启动处理
    processor.process(input_file)