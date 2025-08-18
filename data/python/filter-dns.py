#!/usr/bin/env python3
"""
高效黑名单处理器 - 重构版
支持：AdGuard Home规则验证 | Hosts文件提取 | 多协议DNS验证
"""

# ======================
# 配置区（Python语法变量）
# ======================

# DNS配置
DNS_VALIDATION = True  # DNS验证开关
WHOIS_ENABLED = False   # WHOIS检查开关
CI_MODE = True          # CI环境模式

# 协议配置
PREFER_DOH = True      # 优先DoH协议
PREFER_DOT = False     # 次选DoT协议

# 路径配置
INPUT_PATH = "adblock.txt"         # 输入文件（位于仓库根目录）
OUTPUT_ADGUARD = "dns.txt"         # AdGuard输出（位于仓库根目录）
OUTPUT_HOSTS = "hosts.txt"         # Hosts输出（位于仓库根目录）

# 性能配置
MAX_WORKERS = 8
BATCH_SIZE = 10000
TIMEOUT = 5
RETRIES = 2

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
import ssl
import base64
import threading
import subprocess
from pathlib import Path
from typing import Tuple, List, Set, Optional, Dict, Any
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import requests
import dns.resolver
import dns.message
import dns.rdatatype

# 初始化日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

class PathResolver:
    """路径解析器"""
    @staticmethod
    def get_script_dir() -> Path:
        """获取脚本所在目录"""
        return Path(__file__).parent.resolve()

    @staticmethod
    def resolve_path(relative_path: str) -> Path:
        """解析相对路径为绝对路径"""
        script_dir = PathResolver.get_script_dir()
        # 直接设置基础目录为仓库根目录（脚本目录的上两级目录）
        base_dir = script_dir.parent.parent
        return (base_dir / relative_path).resolve()

class ConfigLoader:
    """配置加载器（单例模式）"""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        self.config = configparser.ConfigParser()

        # 从Python变量加载配置
        self.config.read_dict({
            'DNS': {
                'validation': DNS_VALIDATION,
                'whois': WHOIS_ENABLED,
                'ci': CI_MODE
            },
            'Protocol': {
                'prefer_doh': PREFER_DOH,
                'prefer_dot': PREFER_DOT
            },
            'Paths': {
                'input': INPUT_PATH,
                'output_adguard': OUTPUT_ADGUARD,
                'output_hosts': OUTPUT_HOSTS
            },
            'Performance': {
                'max_workers': MAX_WORKERS,
                'batch_size': BATCH_SIZE,
                'timeout': TIMEOUT,
                'retries': RETRIES
            }
        })

        # 环境变量覆盖
        self._apply_env_overrides()

        # 初始化DNS服务器和正则
        self._init_dns_servers()
        self._init_regex_patterns()

        # 解析路径
        self._resolve_paths()

    def _apply_env_overrides(self):
        env_map = {
            'DNS_VALIDATION': ('DNS', 'validation'),
            'WHOIS_ENABLED': ('DNS', 'whois'),
            'IS_CI': ('DNS', 'ci'),
            'PREFER_DOH': ('Protocol', 'prefer_doh'),
            'PREFER_DOT': ('Protocol', 'prefer_dot')
        }

        for env_var, (section, key) in env_map.items():
            if env_var in os.environ:
                self.config[section][key] = os.environ[env_var].lower()

    def _resolve_paths(self):
        """解析所有路径为绝对路径"""
        for key in ['input', 'output_adguard', 'output_hosts']:
            rel_path = self.config.get('Paths', key)
            abs_path = PathResolver.resolve_path(rel_path)
            self.config['Paths'][key] = str(abs_path)

    def _init_dns_servers(self):
        """初始化DNS服务器配置 - 混合交叉验证策略"""
        # 混合国内和国际DNS服务器
        self.dns_servers = {
            # 国内DNS服务器
            "cn_servers": [
                {"doh": "https://dns.alidns.com/dns-query", "dot": "tls://dns.alidns.com", "udp": "223.5.5.5"},
                {"doh": "https://doh.pub/dns-query", "dot": "tls://dot.pub", "udp": "119.29.29.29"},
                {"udp": "223.6.6.6"},
                {"udp": "114.114.114.114"},
                {"udp": "114.114.115.115"},
                {"doh": "https://dns.twnic.tw/dns-query", "udp": "101.101.101.101"},
                {"doh": "https://doh.dns.sb/dns-query", "udp": "185.222.222.222"}
            ],
            # 国际DNS服务器
            "intl_servers": [
                {"doh": "https://cloudflare-dns.com/dns-query", "dot": "tls://1.1.1.1", "udp": "1.1.1.1"},
                {"doh": "https://dns.google/dns-query", "dot": "tls://dns.google", "udp": "8.8.8.8"},
                {"doh": "https://doh.opendns.com/dns-query", "udp": "208.67.222.222"},
                {"doh": "https://dns.quad9.net/dns-query", "udp": "9.9.9.9"},
                {"doh": "https://dns.nextdns.io/dns-query", "udp": "45.90.28.0"}
            ]
        }

        # 协议权重 - 调整为更平衡的策略
        self.protocol_weights = {
            "doh": 0.5 if self.getbool('Protocol', 'prefer_doh') else 0.3,
            "dot": 0.3 if self.getbool('Protocol', 'prefer_dot') else 0.2,
            "udp": 0.2
        }

    def _init_regex_patterns(self):
        """初始化正则表达式"""
        self.regex = {
            # AdGuard规则匹配
            'adguard': [
                re.compile(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)"),  # 基础规则
                re.compile(r"^([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\$"),          # 域名规则
                re.compile(r"^\*\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)"), # 通配符
                re.compile(r"^\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/"),       # 路径规则
            ],
            # Hosts规则匹配
            'hosts': [
                re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([^\s#]+)"),       # 标准格式
                re.compile(r"^\s*([^\s#]+)\s+([^\s#]+)")                   # 简化格式
            ],
            # 排除规则
            'exclusions': [
                re.compile(r"^@@"),  # 放行规则
                re.compile(r"^#"),   # 注释
                re.compile(r"^!")    # 注释
            ]
        }

    def getbool(self, section: str, key: str) -> bool:
        return self.config.getboolean(section, key)

    def getint(self, section: str, key: str) -> int:
        return self.config.getint(section, key)

    def get(self, section: str, key: str) -> str:
        return self.config.get(section, key)

class DNSValidator:
    """DNS验证器 - 混合交叉验证策略"""
    def __init__(self):
        self.config = ConfigLoader()
        self._init_resolvers()
        # 混合所有服务器
        self.all_servers = []
        for group in self.config.dns_servers.values():
            self.all_servers.extend(group)

    def _init_resolvers(self):
        self.resolvers = {proto: [] for proto in ['doh', 'dot', 'udp']}
        for group in self.config.dns_servers.values():
            for server in group:
                for proto in ['doh', 'dot', 'udp']:
                    if proto in server:
                        self.resolvers[proto].append(server[proto])

    def query(self, domain: str) -> bool:
        """执行DNS查询 - 混合交叉验证策略"""
        # 尝试所有协议和所有服务器，只要有一个成功就返回True
        protocols = list(self.config.protocol_weights.keys())
        random.shuffle(protocols)
        
        for proto in protocols:
            if not self.resolvers.get(proto):
                continue
                
            # 随机打乱服务器顺序
            servers = self.resolvers[proto][:]
            random.shuffle(servers)
            
            for server in servers:
                try:
                    if proto == "doh":
                        if self._doh_query(server, domain):
                            return True
                    elif proto == "dot":
                        if self._dot_query(server, domain):
                            return True
                    else:
                        if self._udp_query(server, domain):
                            return True
                except Exception as e:
                    logger.debug(f"DNS查询失败: {proto}://{server} {domain} - {str(e)}")
                    continue
        
        # 如果所有协议都失败，尝试备用方案
        return self._fallback_query(domain)

    def _fallback_query(self, domain: str) -> bool:
        """备用查询方案 - 使用系统DNS和混合服务器"""
        try:
            # 首先尝试系统DNS解析
            socket.getaddrinfo(domain, 80)
            return True
        except socket.gaierror:
            pass
        
        # 尝试所有服务器混合查询
        all_servers = []
        for proto in ['udp', 'doh', 'dot']:
            if proto in self.resolvers:
                all_servers.extend([(proto, s) for s in self.resolvers[proto]])
        
        random.shuffle(all_servers)
        
        for proto, server in all_servers:
            try:
                if proto == "doh":
                    if self._doh_query(server, domain):
                        return True
                elif proto == "dot":
                    if self._dot_query(server, domain):
                        return True
                else:
                    if self._udp_query(server, domain):
                        return True
            except Exception:
                continue
        
        return False

    def _doh_query(self, server: str, domain: str) -> bool:
        """DoH查询实现"""
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            b64_data = base64.urlsafe_b64encode(query.to_wire()).decode().rstrip("=")
            resp = requests.get(
                f"{server}?dns={b64_data}",
                headers={"Accept": "application/dns-message"},
                timeout=self.config.getint('Performance', 'timeout')
            )
            resp.raise_for_status()
            return len(dns.message.from_wire(resp.content).answer) > 0
        except Exception as e:
            logger.debug(f"DoH查询失败: {server} {domain} - {str(e)}")
            return False

    def _dot_query(self, server: str, domain: str) -> bool:
        """DoT查询实现"""
        try:
            host = server.split("://")[-1].split(":")[0]
            with socket.create_connection((host, 853), 
                  timeout=self.config.getint('Performance', 'timeout')) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    tls_sock.sendall(dns.message.make_query(domain, dns.rdatatype.A).to_wire())
                    return len(dns.message.from_wire(tls_sock.recv(1024)).answer) > 0
        except Exception as e:
            logger.debug(f"DoT查询失败: {server} {domain} - {str(e)}")
            return False

    def _udp_query(self, server: str, domain: str) -> bool:
        """UDP查询实现"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.timeout = self.config.getint('Performance', 'timeout')
            resolver.lifetime = self.config.getint('Performance', 'timeout') * \
                              self.config.getint('Performance', 'retries')
            resolver.resolve(domain, "A")
            return True
        except Exception as e:
            logger.debug(f"UDP查询失败: {server} {domain} - {str(e)}")
            return False

class WHOISValidator:
    """WHOIS验证器"""
    def __init__(self):
        self.config = ConfigLoader()
    
    def is_domain_expired(self, domain: str) -> bool:
        """检查域名是否过期"""
        if not self.config.getbool('DNS', 'whois'):
            return False
        
        # 顶级域名缓存
        tld_cache = {
            "com": "whois.verisign-grs.com",
            "net": "whois.verisign-grs.com",
            "org": "whois.pir.org",
            "cn": "whois.cnnic.cn",
            "uk": "whois.nic.uk",
            "de": "whois.denic.de",
            "jp": "whois.jprs.jp",
            "ru": "whois.tcinet.ru",
            "br": "whois.registro.br",
            "in": "whois.registry.in",
            "fr": "whois.nic.fr",
            "au": "whois.auda.org.au",
            "ca": "whois.cira.ca",
            "nl": "whois.domain-registry.nl",
            "eu": "whois.eu",
            "ch": "whois.nic.ch",
            "it": "whois.nic.it",
            "es": "whois.nic.es",
            "se": "whois.iis.se",
            "no": "whois.norid.no",
            "dk": "whois.dk-hostmaster.dk",
            "fi": "whois.fi",
            "pl": "whois.dns.pl",
            "be": "whois.dns.be",
            "at": "whois.nic.at",
            "nz": "whois.srs.net.nz",
            "kr": "whois.kr",
            "sg": "whois.sgnic.sg",
            "hk": "whois.hkirc.hk",
            "tw": "whois.twnic.net.tw",
            "mx": "whois.mx",
            "co": "whois.nic.co",
            "io": "whois.nic.io",
            "ai": "whois.nic.ai",
            "me": "whois.nic.me",
            "tv": "whois.nic.tv",
            "cc": "whois.nic.cc",
            "info": "whois.afilias.net",
            "biz": "whois.nic.biz"
        }
        
        # 提取TLD
        tld = domain.split('.')[-1].lower()
        whois_server = tld_cache.get(tld, f"whois.iana.org")
        
        try:
            # 执行WHOIS查询
            result = subprocess.run(
                ["whois", "-h", whois_server, domain],
                capture_output=True,
                text=True,
                timeout=self.config.getint('Performance', 'timeout'),
                check=True
            )
            output = result.stdout.lower()
            
            # 检查过期状态的关键词
            expired_keywords = [
                "expired", "expiration", "expiry", "expires on",
                "domain expired", "domain expiration", "status: expired",
                "no match", "not found", "invalid", "available",
                "redemption period", "pending delete", "clienthold"
            ]
            
            # 检查是否包含过期关键词
            if any(keyword in output for keyword in expired_keywords):
                logger.debug(f"域名已过期: {domain}")
                return True
            
            # 检查注册状态关键词
            status_keywords = [
                "active", "ok", "registered", "valid", "paid"
            ]
            
            # 检查是否包含有效状态关键词
            if any(keyword in output for keyword in status_keywords):
                return False
            
            # 如果没有找到明确状态，默认为有效
            return False
        except Exception as e:
            logger.debug(f"WHOIS查询失败: {domain} - {str(e)}")
            return False

class RuleValidator:
    """规则验证器"""
    def __init__(self):
        self.config = ConfigLoader()
        self.dns = DNSValidator()
        self.whois = WHOISValidator()
        self.cache = {
            'valid_domains': set(),
            'invalid_domains': set(),
            'whois': {}
        }
        self.lock = threading.Lock()
    
    def validate_rule(self, rule: str) -> Tuple[Optional[str], Optional[List[str]]]:
        """验证单条规则"""
        # 排除无效规则
        if any(pattern.match(rule) for pattern in self.config.regex['exclusions']):
            return None, None
        
        # 尝试解析为AdGuard规则
        adguard_rule = self._parse_adguard(rule)
        if adguard_rule:
            return self._validate_adguard(adguard_rule)
        
        # 尝试解析为Hosts规则
        hosts_rule = self._parse_hosts(rule)
        if hosts_rule:
            return self._validate_hosts(hosts_rule)
        
        return None, None
    
    def _parse_adguard(self, rule: str) -> Optional[Dict]:
        """解析AdGuard规则"""
        for pattern in self.config.regex['adguard']:
            match = pattern.match(rule)
            if match:
                return {
                    'type': 'adguard',
                    'original': rule,
                    'domain': match.group(1).lower(),
                    'full_match': match.group(0)
                }
        return None
    
    def _parse_hosts(self, rule: str) -> Optional[Dict]:
        """解析Hosts规则"""
        for pattern in self.config.regex['hosts']:
            match = pattern.match(rule)
            if match:
                return {
                    'type': 'hosts',
                    'original': rule,
                    'ip': match.group(1),
                    'domains': [d.lower() for d in match.group(2).split()]
                }
        return None
    
    def _validate_adguard(self, rule: Dict) -> Tuple[Optional[str], Optional[List[str]]]:
        """验证AdGuard规则"""
        if not self._is_domain_valid(rule['domain']):
            return None, None
        
        # 生成Hosts格式规则
        hosts_rules = [f"0.0.0.0 {rule['domain']}"] if rule['domain'].startswith(('||', '*.')) else None
        
        return rule['original'], hosts_rules
    
    def _validate_hosts(self, rule: Dict) -> Tuple[Optional[str], Optional[List[str]]]:
        """验证Hosts规则"""
        valid_domains = []
        for domain in rule['domains']:
            if self._is_domain_valid(domain):
                valid_domains.append(domain)
        
        if not valid_domains:
            return None, None
        
        # 重构有效规则
        new_rule = f"{rule['ip']} {' '.join(valid_domains)}"
        return new_rule, [f"{rule['ip']} {d}" for d in valid_domains]
    
    def _is_domain_valid(self, domain: str) -> bool:
        """验证域名有效性"""
        if not self.config.getbool('DNS', 'validation'):
            return True
        
        with self.lock:
            if domain in self.cache['valid_domains']:
                return True
            if domain in self.cache['invalid_domains']:
                return False
        
        is_valid = self.dns.query(domain) and not self._is_domain_expired(domain)
        
        with self.lock:
            if is_valid:
                self.cache['valid_domains'].add(domain)
            else:
                self.cache['invalid_domains'].add(domain)
        
        return is_valid
    
    @lru_cache(maxsize=10000)
    def _is_domain_expired(self, domain: str) -> bool:
        """检查域名过期状态"""
        return self.whois.is_domain_expired(domain)

class BlacklistProcessor:
    """黑名单处理器"""
    def __init__(self):
        self.config = ConfigLoader()
        self.validator = RuleValidator()
        self.results = {
            'adguard': set(),
            'hosts': set()
        }
        self.metrics = {
            'processed': 0,
            'start_time': time.time()
        }
    
    def process(self):
        """主处理流程"""
        logger.info("开始处理规则文件...")
        logger.info(f"输入文件: {self.config.get('Paths', 'input')}")
        logger.info(f"输出位置: {self.config.get('Paths', 'output_adguard')}")
        
        with ThreadPoolExecutor(max_workers=self.config.getint('Performance', 'max_workers')) as executor:
            for batch in self._read_batches():
                futures = []
                for line in batch:
                    futures.append(executor.submit(self.validator.validate_rule, line))
                
                for future in as_completed(futures):
                    self._handle_result(future.result())
                    self._log_progress()
        
        self._save_results()
        self._print_summary()
    
    def _read_batches(self):
        """分批读取输入文件"""
        input_path = self.config.get('Paths', 'input')
        batch = []
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not any(p.match(line) for p in self.config.regex['exclusions']):
                        batch.append(line)
                        if len(batch) >= self.config.getint('Performance', 'batch_size'):
                            yield batch
                            batch = []
                if batch:
                    yield batch
        except FileNotFoundError:
            logger.error(f"输入文件不存在: {input_path}")
            sys.exit(1)
    
    def _handle_result(self, result: Tuple[Optional[str], Optional[List[str]]]):
        """处理验证结果"""
        adguard_rule, hosts_rules = result
        if adguard_rule:
            self.results['adguard'].add(adguard_rule)
        if hosts_rules:
            self.results['hosts'].update(hosts_rules)
        
        self.metrics['processed'] += 1
    
    def _log_progress(self):
        """记录处理进度"""
        if self.metrics['processed'] % 1000 == 0:
            elapsed = time.time() - self.metrics['start_time']
            rate = self.metrics['processed'] / elapsed if elapsed > 0 else 0
            logger.info(
                f"已处理: {self.metrics['processed']} | "
                f"AdGuard规则: {len(self.results['adguard'])} | "
                f"Hosts规则: {len(self.results['hosts'])} | "
                f"速度: {rate:.1f} 条/秒"
            )
    
    def _save_results(self):
        """保存结果文件"""
        # 确保输出目录存在
        for key in ['output_adguard', 'output_hosts']:
            output_path = Path(self.config.get('Paths', key))
            output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 保存AdGuard规则
        with open(self.config.get('Paths', 'output_adguard'), 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.results['adguard'])))
        
        # 保存Hosts规则
        with open(self.config.get('Paths', 'output_hosts'), 'w', encoding='utf-8') as f:
            f.write("\n".join(sorted(self.results['hosts'])))
    
    def _print_summary(self):
        """打印摘要信息"""
        total_time = time.time() - self.metrics['start_time']
        logger.info(
            f"\n处理完成！\n"
            f"总耗时: {total_time:.2f}秒\n"
            f"处理总数: {self.metrics['processed']}\n"
            f"有效AdGuard规则: {len(self.results['adguard'])}\n"
            f"有效Hosts规则: {len(self.results['hosts'])}\n"
            f"输出文件:\n"
            f"- AdGuard: {self.config.get('Paths', 'output_adguard')}\n"
            f"- Hosts: {self.config.get('Paths', 'output_hosts')}"
        )

def main():
    """主入口"""
    try:
        processor = BlacklistProcessor()
        processor.process()
    except KeyboardInterrupt:
        logger.info("用户中断处理")
        sys.exit(0)
    except Exception as e:
        logger.error(f"处理失败: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()