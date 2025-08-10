import os
import asyncio
import aiodns
import time
from pathlib import Path
import re

# ============== 配置部分（与下载脚本完全一致） ==============
INPUT_DIR = "./tmp/"          # 下载脚本的输出目录
OUTPUT_DIR = "./data/rules/"  # 最终规则存放目录
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============== SmartDNS + CDN 优化配置 ==============
class DomainValidator:
    def __init__(self):
        # 国内DNS组（权重根据响应速度动态调整）
        self.china_dns = [
            {'server': '223.5.5.5', 'weight': 10},    # 阿里DNS
            {'server': '119.29.29.29', 'weight': 8},   # 腾讯DNS
            {'server': '114.114.114.114', 'weight': 5}  # 114DNS
        ]
        # 国外DNS组
        self.global_dns = [
            {'server': '8.8.8.8', 'weight': 10},      # Google DNS
            {'server': '1.1.1.1', 'weight': 8},       # Cloudflare
            {'server': '9.9.9.9', 'weight': 5}        # Quad9
        ]
        self.resolvers = self._init_resolvers()
        self.cache = {}  # CDN缓存 {'domain': {'ips': [], 'expire': timestamp}}

    def _init_resolvers(self):
        """初始化异步DNS解析器"""
        return {
            'china': [aiodns.DNSResolver(nameservers=[ns['server']], timeout=2) 
                     for ns in self.china_dns],
            'global': [aiodns.DNSResolver(nameservers=[ns['server']], timeout=2)
                      for ns in self.global_dns]
        }

    async def _query_dns(self, resolver, domain):
        """执行单次DNS查询"""
        try:
            return await resolver.query(domain, 'A')
        except (aiodns.error.DNSError, asyncio.TimeoutError):
            return None

    async def smart_resolve(self, domain):
        """SmartDNS核心逻辑：国内国外双线路+缓存"""
        # 检查CDN缓存
        if domain in self.cache and self.cache[domain]['expire'] > time.time():
            return bool(self.cache[domain]['ips'])
        
        # 并行发起国内国外查询
        tasks = []
        for resolver in self.resolvers['china'] + self.resolvers['global']:
            tasks.append(self._query_dns(resolver, domain))
        
        # 获取首个成功结果
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if result := task.result():
                # 更新缓存（默认TTL 60秒）
                self.cache[domain] = {
                    'ips': [r.host for r in result],
                    'expire': time.time() + 60
                }
                return True
        return False

# ============== 文件处理（严格匹配下载脚本的输出） ==============
def extract_domain(rule):
    """从规则行提取域名（支持多种格式）"""
    patterns = [
        (r'^\|\|([^\/\^\*]+)\^', 2),     # ||domain.com^
        (r'^0\.0\.0\.0\s+([^\s]+)', 1),  # 0.0.0.0 domain.com
        (r'^([^\/\^\*\s]+)$', 0)         # domain.com
    ]
    for pattern, group in patterns:
        match = re.search(pattern, rule)
        if match:
            return match.group(group) if group else match.group()
    return None

async def validate_file(input_path, output_path):
    """处理单个文件（保持原始文件名）"""
    validator = DomainValidator()
    valid_rules = []
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        rules = [line.strip() for line in f if line.strip()]
    
    # 批量验证（每100个域名一组）
    batch_size = 100
    for i in range(0, len(rules), batch_size):
        batch = rules[i:i+batch_size]
        tasks = []
        for rule in batch:
            domain = extract_domain(rule)
            if not domain:  # 非域名规则直接保留
                valid_rules.append(rule)
                continue
            tasks.append(validator.smart_resolve(domain))
        
        results = await asyncio.gather(*tasks)
        valid_rules.extend(rule for rule, is_valid in zip(batch, results) if is_valid)
    
    # 写入同名文件到输出目录
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_rules))

# ============== 主流程（兼容下载脚本的输出结构） ==============
async def main():
    start_time = time.time()
    
    # 处理所有下载脚本生成的文件
    for rule_type in ['adblock', 'allow']:
        for input_file in Path(INPUT_DIR).glob(f"{rule_type}*.txt"):
            output_file = Path(OUTPUT_DIR) / input_file.name  # 保持同名
            await validate_file(input_file, output_file)
            print(f"✅ 已处理: {input_file.name} -> {output_file}")
    
    print(f"⏱️ 总耗时: {time.time()-start_time:.2f}秒")

if __name__ == "__main__":
    asyncio.run(main())