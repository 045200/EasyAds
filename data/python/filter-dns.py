#!/usr/bin/env python3
"""
高效黑名单处理器 - CI优化版
支持完整 AdGuard Home 语法 | 特殊语法跳过验证 | GitHub CI 优化
"""

# ======================
# 配置区
# ======================
INPUT_FILE = "adblock.txt"         # 输入文件
OUTPUT_ADGUARD = "dns.txt"         # AdGuard输出
OUTPUT_HOSTS = "hosts.txt"         # Hosts输出
MAX_WORKERS = 4                    # CI环境推荐4工作线程
TIMEOUT = 2                        # CI环境推荐2秒超时
DNS_VALIDATION = True              # DNS验证开关
BATCH_SIZE = 5000                  # 分批处理大小

# ======================
# 脚本主体
# ======================
import os
import sys
import re
import time
import random
import logging
import socket
import concurrent.futures
from pathlib import Path
from typing import Tuple, Optional, List, Set, Iterator

# 预编译正则表达式 - 提升性能
ADG_SPECIAL = re.compile(r'^!|^\$|^@@|^/.*/$|^\|\|.*\^|\*\.|^\|\|.*/|^\|http?://|^##|^#\?#|^\?|\|\|.*\^\$')
ADG_DOMAIN = re.compile(r'^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)|^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\$|^\*\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)')
HOSTS_RULE = re.compile(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([^\s#]+)')
COMMENT_RULE = re.compile(r'^[!#]|^\[Adblock')
EXCEPTION_RULE = re.compile(r'^@@')

# 初始化日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class PathResolver:
    """路径解析器 - 优化内存使用"""
    @staticmethod
    def resolve_path(relative_path: str) -> Path:
        """解析相对路径为绝对路径"""
        script_dir = Path(__file__).parent.resolve()
        return (script_dir.parent.parent / relative_path).resolve()

class RuleValidator:
    """规则验证器 - 预编译正则优化"""
    # DNS服务器 - 使用元组减少内存占用
    DNS_SERVERS = (
        "223.5.5.5",        # 阿里DNS
        "119.29.29.29",     # 腾讯DNS
        "1.1.1.1",          # Cloudflare
        "8.8.8.8",          # Google DNS
    )
    
    def __init__(self):
        # 使用集合存储域名缓存
        self.valid_domains = set()
        self.invalid_domains = set()
    
    def validate_rule(self, rule: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """验证单条规则 - 优化性能"""
        # 跳过注释和头部声明
        if COMMENT_RULE.match(rule):
            return None, None
        
        # 跳过例外规则
        if EXCEPTION_RULE.match(rule):
            return None, None
        
        # 特殊语法直接写入
        if ADG_SPECIAL.match(rule):
            return rule, None
        
        # 尝试解析为AdGuard规则
        if domain := self._parse_adguard(rule):
            if not DNS_VALIDATION or self._is_domain_valid(domain):
                return rule, [f"0.0.0.0 {domain}"]
            return None, None
        
        # 尝试解析为Hosts规则
        if result := self._parse_hosts(rule):
            ip, domains = result
            valid_domains = [d for d in domains if not DNS_VALIDATION or self._is_domain_valid(d)]
            if not valid_domains:
                return None, None
            return f"{ip} {' '.join(valid_domains)}", [f"{ip} {d}" for d in valid_domains]
        
        # 无法识别的规则直接写入
        return rule, None
    
    def _parse_adguard(self, rule: str) -> Optional[str]:
        """解析AdGuard规则 - 使用预编译正则"""
        if match := ADG_DOMAIN.match(rule):
            # 返回第一个非空匹配组
            return next((g for g in match.groups() if g), "").lower()
        return None
    
    def _parse_hosts(self, rule: str) -> Optional[Tuple[str, List[str]]]:
        """解析Hosts规则 - 使用预编译正则"""
        if match := HOSTS_RULE.match(rule):
            ip = match.group(1)
            domains = [d.lower() for d in match.group(2).split()]
            return ip, domains
        return None
    
    def _is_domain_valid(self, domain: str) -> bool:
        """验证域名有效性 - 使用缓存优化"""
        if domain in self.valid_domains:
            return True
        if domain in self.invalid_domains:
            return False
        
        is_valid = self._dns_query(domain)
        
        if is_valid:
            self.valid_domains.add(domain)
        else:
            self.invalid_domains.add(domain)
        
        return is_valid
    
    def _dns_query(self, domain: str) -> bool:
        """DNS查询实现 - 精简高效版"""
        # 尝试系统DNS - 最快方式
        try:
            socket.getaddrinfo(domain, 80)
            return True
        except socket.gaierror:
            pass
        
        # 随机选择DNS服务器
        server = random.choice(self.DNS_SERVERS)
        
        # 使用UDP套接字查询
        try:
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.settimeout(TIMEOUT)
            
            # 构造精简DNS查询
            query_id = random.randint(0, 65535)
            query = bytearray()
            query += query_id.to_bytes(2, 'big')  # 事务ID
            query += b"\x01\x00"                  # 标志
            query += b"\x00\x01"                  # 问题数
            query += b"\x00\x00" * 3              # 其他部分置零
            
            # 域名编码
            for part in domain.encode().split(b"."):
                query.append(len(part))
                query += part
            query += b"\x00"                      # 结束
            
            query += b"\x00\x01"                  # A记录
            query += b"\x00\x01"                  # IN类
            
            # 发送并接收
            resolver.sendto(query, (server, 53))
            response, _ = resolver.recvfrom(512)
            
            # 基础验证: 响应长度、事务ID、响应码
            return (len(response) > 12 and 
                    response[:2] == query_id.to_bytes(2, 'big') and
                    response[3] & 0x0F == 0)
        except Exception:
            return False

class BlacklistProcessor:
    """黑名单处理器 - 内存优化版"""
    def __init__(self):
        self.validator = RuleValidator()
        self.adguard_rules = set()
        self.hosts_rules = set()
        self.processed_count = 0
        self.start_time = time.time()
    
    def process(self):
        """主处理流程 - 分批处理优化内存"""
        logger.info("启动规则处理 (CI优化版)")
        input_path = PathResolver.resolve_path(INPUT_FILE)
        logger.info(f"输入文件: {input_path}")
        
        # 分批处理文件
        for batch in self._read_batches(input_path):
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(self.validator.validate_rule, line) for line in batch]
                
                for future in concurrent.futures.as_completed(futures):
                    self._handle_result(future.result())
                    self._log_progress()
        
        self._save_results()
        self._print_summary()
    
    def _read_batches(self, input_path: Path) -> Iterator[List[str]]:
        """分批读取文件 - 减少内存占用"""
        batch = []
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                if stripped := line.strip():
                    batch.append(stripped)
                    if len(batch) >= BATCH_SIZE:
                        yield batch
                        batch = []
            if batch:
                yield batch
    
    def _handle_result(self, result: Tuple[Optional[str], Optional[List[str]]]):
        """处理验证结果 - 精简高效"""
        adguard_rule, hosts_rules = result
        if adguard_rule:
            self.adguard_rules.add(adguard_rule)
        if hosts_rules:
            self.hosts_rules.update(hosts_rules)
        self.processed_count += 1
    
    def _log_progress(self):
        """记录处理进度 - 减少日志频率"""
        if self.processed_count % 2000 == 0:  # 减少日志频率
            elapsed = time.time() - self.start_time
            rate = self.processed_count / elapsed if elapsed > 0 else 0
            logger.info(
                f"已处理: {self.processed_count} | "
                f"AdGuard规则: {len(self.adguard_rules)} | "
                f"Hosts规则: {len(self.hosts_rules)} | "
                f"速度: {rate:.1f} 条/秒"
            )
    
    def _save_results(self):
        """保存结果文件 - 流式写入"""
        # AdGuard规则
        adguard_path = PathResolver.resolve_path(OUTPUT_ADGUARD)
        adguard_path.parent.mkdir(parents=True, exist_ok=True)
        with open(adguard_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.adguard_rules)))
        
        # Hosts规则
        hosts_path = PathResolver.resolve_path(OUTPUT_HOSTS)
        with open(hosts_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.hosts_rules)))
    
    def _print_summary(self):
        """打印摘要信息 - 精简输出"""
        total_time = time.time() - self.start_time
        logger.info(
            f"处理完成! 耗时: {total_time:.1f}秒 | "
            f"总数: {self.processed_count} | "
            f"AdGuard规则: {len(self.adguard_rules)} | "
            f"Hosts规则: {len(self.hosts_rules)}"
        )
        logger.info(f"输出文件: {OUTPUT_ADGUARD}, {OUTPUT_HOSTS}")

if __name__ == "__main__":
    try:
        processor = BlacklistProcessor()
        processor.process()
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("处理已中断")
        sys.exit(1)
    except Exception as e:
        logger.error(f"处理失败: {str(e)}")
        sys.exit(1)