#!/usr/bin/env python3
"""
AdGuard Home 规则专业处理器 - 20万规则优化版
功能：合并、去重、验证、分类输出AdGuard和Hosts规则
"""

import dns.resolver
import re
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import sys
import psutil

class UltraRuleProcessor:
    # DNS服务器配置（国内外混合）
    DNS_SERVERS = [
        '1.1.1.1',      # Cloudflare
        '8.8.8.8',      # Google
        '223.5.5.5',    # 阿里
        '119.29.29.29'  # DNSPod
    ]
    
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

    # 自动排除的域名后缀
    EXCLUDE_SUFFIXES = {
        '.cloudfront.net', '.akamai.net',
        '.cdn.cloudflare.net', '.local',
        '.internal', '.localhost'
    }

    def __init__(self):
        # 内存优化配置
        self.batch_size = 10000  # 每批处理量
        self.max_workers = 10     # CI最佳并发数
        
        # 初始化DNS解析器
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1.5
        self.resolver.lifetime = 2
        self.resolver.nameservers = self.DNS_SERVERS

    def process(self, input_path: Path):
        """主处理流程"""
        print(f"[INFO] 开始处理规则文件: {input_path}")
        start_time = time.time()
        
        # 输出文件配置
        output_dir = input_path.parent
        adg_path = output_dir / "adguard.txt"
        hosts_path = output_dir / "hosts.txt"
        
        # 内存监控
        mem_start = self._get_memory()
        
        # 分批处理大文件
        adg_rules, hosts_rules = set(), set()
        for batch in self._batch_reader(input_path):
            batch_adg, batch_hosts = self._process_batch(batch)
            adg_rules.update(batch_adg)
            hosts_rules.update(batch_hosts)
            
            # 实时进度输出
            print(
                f"\r[STATUS] 处理进度: {len(adg_rules)+len(hosts_rules)}条 | "
                f"内存: {self._get_memory():.1f}MB", 
                end='', flush=True
            )
        
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

    def _batch_reader(self, path: Path):
        """大文件分批读取器"""
        with path.open('r', encoding='utf-8', errors='ignore') as f:
            batch = []
            for line in f:
                if line.strip():
                    batch.append(line.strip())
                    if len(batch) >= self.batch_size:
                        yield batch
                        batch = []
            if batch:
                yield batch

    def _process_batch(self, batch: list) -> tuple:
        """处理单批次规则"""
        adg_rules, hosts_rules = set(), set()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
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

    def _parse_rule(self, rule: str) -> tuple:
        """解析单条规则"""
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
            if not self._dns_lookup(domain):
                return None, None
            
            # Hosts转换（仅基础规则）
            hosts_rule = None
            if rule.startswith('||') and rule.endswith('^'):
                hosts_rule = f"0.0.0.0 {domain}"
            
            return rule, hosts_rule
        
        # 2. Hosts规则处理
        elif self._is_hosts_rule(rule):
            parts = rule.split()
            domain = parts[1] if len(parts) >= 2 else None
            
            if domain and not any(domain.endswith(s) for s in self.EXCLUDE_SUFFIXES):
                if self._dns_lookup(domain):
                    return None, rule  # 仅保留Hosts
        
        return None, None

    def _extract_domain(self, rule: str) -> str:
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
        try:
            # 轮询所有DNS服务器
            for server in self.DNS_SERVERS:
                self.resolver.nameservers = [server]
                try:
                    answer = self.resolver.resolve(domain, 'A', raise_on_no_answer=False)
                    if answer.rrset is not None:
                        return True
                except:
                    continue
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
        input_file = Path(__file__).parent.parent.parents / "adblock.txt"
    
    if not input_file.exists():
        print(f"[ERROR] 输入文件不存在: {input_file}")
        sys.exit(1)

    # 启动处理器
    processor = UltraRuleProcessor()
    processor.process(input_file)