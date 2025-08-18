import dns.resolver
from pathlib import Path

class RuleProcessor:
    """AdGuard Home & Hosts规则处理器（路径修复版）"""
    def __init__(self):
        # 配置DNS解析器（CI优化参数）
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1.5  # 短超时适应CI环境
        self.resolver.lifetime = 2
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8']  # 国际DNS

    def process(self):
        """从仓库根目录读取/写入文件"""
        # 路径解析（关键修复点）
        base_dir = Path(__file__).parent.parent  # /data/python/ → 仓库根目录
        input_path = base_dir / "adblock.txt"
        dns_output = base_dir / "adguard.txt"
        hosts_output = base_dir / "hosts.txt"

        # 验证输入文件存在
        if not input_path.exists():
            raise FileNotFoundError(f"输入文件不存在: {input_path}")

        # 处理规则
        with input_path.open('r', encoding='utf-8') as f:
            rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        dns_rules, hosts_rules = set(), set()
        
        for rule in rules:
            if rule.startswith('||') and '^' in rule:  # AdGuard格式
                domain = rule.split('^')[0][2:]
                if self._check_domain(domain):
                    dns_rules.add(rule)
                    hosts_rules.add(f"0.0.0.0 {domain}")
            
            elif ' ' in rule:  # Hosts格式
                parts = rule.split()
                if len(parts) == 2 and self._check_domain(parts[1]):
                    hosts_rules.add(rule)

        # 确保输出目录存在并写入
        self._write_file(dns_output, sorted(dns_rules))
        self._write_file(hosts_output, sorted(hosts_rules))
        
        print(f"生成文件: {dns_output.name}({len(dns_rules)}条), {hosts_output.name}({len(hosts_rules)}条)")

    def _check_domain(self, domain: str) -> bool:
        """DNS存活检查（静默模式）"""
        try:
            self.resolver.resolve(domain, 'A')
            return True
        except:
            return False

    def _write_file(self, path: Path, lines: list):
        """原子化写入（防CI中断）"""
        path.parent.mkdir(exist_ok=True)  # 确保目录存在
        temp_path = path.with_suffix('.tmp')
        with temp_path.open('w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        temp_path.replace(path)

if __name__ == "__main__":
    RuleProcessor().process()