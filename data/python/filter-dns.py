import dns.resolver
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import time

class AdvancedRuleProcessor:
    """AdGuard Home 和 Hosts 规则专业处理器"""
    
    def __init__(self):
        # DNS 配置（优化国内外解析）
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 3
        self.resolver.nameservers = [
            '1.1.1.1',       # Cloudflare（国际）
            '8.8.8.8',       # Google（国际）
            '223.5.5.5',     # 阿里（国内）
            '119.29.29.29'   # DNSPod（国内）
        ]
        
        # 预编译正则（提升性能）
        self.ADG_PATTERN = re.compile(
            r'^(\|\|[\w.-]+\^($|[\w,=-]+)?)|'          # 基础规则
            r'^@@\|\|[\w.-]+\^($|[\w,=-]+)?|'          # 白名单
            r'^\|\|[\w.-]+\^\$dnsrewrite=\S+|'         # DNS重写
            r'^\|\|[\w.-]+\^\$dnstype=\w+|'            # DNS类型
            r'^\|\|[\w.-]+\^\$client=\S+|'             # 客户端
            r'^/[\w\W]+/\$?[\w,=-]*|'                  # 正则
            r'^##.+|'                                  # 元素隐藏
            r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$'          # Hosts
        )
        
        # 排除域名（CDN/内网等）
        self.EXCLUDED_DOMAINS = {
            '.cloudfront.net', '.akamaized.net',
            '.cdn.cloudflare.net', '.local',
            '.internal', '.localhost'
        }

    def process(self):
        """主处理流程"""
        start_time = time.time()
        base_dir = Path(__file__).parent.parent
        
        # 输入输出路径
        input_file = base_dir / "adblock.txt"
        adg_file = base_dir / "adguard.txt"
        hosts_file = base_dir / "hosts.txt"
        
        # 读取规则
        with input_file.open('r', encoding='utf-8', errors='ignore') as f:
            rules = [line.strip() for line in f if line.strip()]
        
        # 分类处理
        adg_rules, hosts_rules = self._classify_rules(rules)
        
        # 写入文件
        self._atomic_write(adg_file, adg_rules)
        self._atomic_write(hosts_file, hosts_rules)
        
        # 性能统计
        elapsed = time.time() - start_time
        print(
            f"处理完成 | AdGuard: {len(adg_rules)}条 | Hosts: {len(hosts_rules)}条 | "
            f"耗时: {elapsed:.1f}s | 内存: {self._get_memory():.1f}MB"
        )

    def _classify_rules(self, rules: list) -> tuple:
        """规则分类核心逻辑"""
        adg_rules = set()
        hosts_rules = set()
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for rule in rules:
                futures.append(executor.submit(
                    self._process_single_rule,
                    rule
                ))
            
            for future in concurrent.futures.as_completed(futures):
                adg_rule, hosts_rule = future.result()
                if adg_rule:
                    adg_rules.add(adg_rule)
                if hosts_rule:
                    hosts_rules.add(hosts_rule)
        
        return sorted(adg_rules), sorted(hosts_rules)

    def _process_single_rule(self, rule: str) -> tuple:
        """单条规则处理"""
        # 跳过注释
        if rule.startswith(('#', '!')):
            return (None, None)
        
        # 1. AdGuard Home 规则处理
        if self.ADG_PATTERN.match(rule):
            domain = self._extract_domain(rule)
            
            # 排除CDN/内网域名
            if domain and any(domain.endswith(ex) for ex in self.EXCLUDED_DOMAINS):
                return (None, None)
                
            # DNS验证
            if domain and not self._dns_lookup(domain):
                return (None, None)
            
            # 保留原始规则
            adg_rule = rule
            
            # 转换基础规则为Hosts
            hosts_rule = None
            if rule.startswith('||') and rule.endswith('^'):
                hosts_rule = f"0.0.0.0 {domain}"
            
            return (adg_rule, hosts_rule)
        
        # 2. 标准Hosts规则处理
        elif self._is_hosts_rule(rule):
            parts = rule.split()
            domain = parts[1] if len(parts) >= 2 else None
            
            if domain and not any(domain.endswith(ex) for ex in self.EXCLUDED_DOMAINS):
                if self._dns_lookup(domain):
                    return (None, rule)  # 只保留Hosts规则
        
        return (None, None)

    def _extract_domain(self, rule: str) -> str:
        """从规则提取域名（支持所有AdGuard语法）"""
        if rule.startswith(('||', '@@||')) and '^' in rule:
            return rule.split('^')[0][2:] if rule.startswith('||') else rule.split('^')[0][4:]
        elif rule.startswith(('address=', '/')):
            return urlparse('//' + rule.split('=')[1].split('/')[1]).hostname
        elif ' ' in rule:  # Hosts
            return rule.split()[1]
        return None

    def _is_hosts_rule(self, rule: str) -> bool:
        """验证Hosts格式"""
        parts = rule.split()
        if len(parts) < 2:
            return False
            
        # 验证IPv4/IPv6
        ip = parts[0]
        if ':' in ip:  # IPv6
            return True
        ip_parts = ip.split('.')
        return (
            len(ip_parts) == 4 and 
            all(p.isdigit() and 0 <= int(p) <= 255 for p in ip_parts)
        )

    def _dns_lookup(self, domain: str) -> bool:
        """DNS验证（含DNSSEC检查）"""
        try:
            # 检查A记录和CNAME
            answer = self.resolver.resolve(domain, 'A', raise_on_no_answer=False)
            if answer.rrset is not None:
                return True
                
            # 检查DNSSEC签名
            answer = self.resolver.resolve(domain, 'DNSKEY')
            return True
        except:
            return False

    def _atomic_write(self, path: Path, lines: list):
        """原子化写入文件"""
        path.parent.mkdir(exist_ok=True)
        temp_path = path.with_suffix('.tmp')
        with temp_path.open('w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        temp_path.replace(path)

    def _get_memory(self) -> float:
        """获取内存占用（MB）"""
        import os, psutil
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024

if __name__ == "__main__":
    processor = AdvancedRuleProcessor()
    processor.process()