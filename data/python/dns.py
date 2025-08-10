import os
import asyncio
import aiodns
import time
from pathlib import Path
import re
import uvloop

# ============== 配置部分 ==============
INPUT_DIR = "./tmp/"
OUTPUT_DIR = "./data/rules/"
os.makedirs(OUTPUT_DIR, exist_ok=True)

class RuleValidator:
    def __init__(self):
        uvloop.install()
        self.loop = asyncio.get_event_loop()
        
        # 三组国内外DNS配置（共6个服务器）
        self.resolver_groups = {
            # 国内组（低延迟）
            'cn': [
                aiodns.DNSResolver(nameservers=['223.5.5.5'], loop=self.loop, timeout=1.5),    # 阿里
                aiodns.DNSResolver(nameservers=['119.29.29.29'], loop=self.loop, timeout=1.5), # 腾讯
                aiodns.DNSResolver(nameservers=['114.114.114.114'], loop=self.loop, timeout=1.5) # 114
            ],
            # 海外组（标准）
            'intl': [
                aiodns.DNSResolver(nameservers=['8.8.8.8'], loop=self.loop, timeout=2.5),      # Google
                aiodns.DNSResolver(nameservers=['1.1.1.1'], loop=self.loop, timeout=2.5),     # Cloudflare
                aiodns.DNSResolver(nameservers=['9.9.9.9'], loop=self.loop, timeout=2.5)      # Quad9
            ],
            # 备用组（混合）
            'backup': [
                aiodns.DNSResolver(nameservers=['180.76.76.76'], loop=self.loop, timeout=2),  # 百度
                aiodns.DNSResolver(nameservers=['208.67.222.222'], loop=self.loop, timeout=3) # OpenDNS
            ]
        }
        self.cache = {}
        self.rule_formats = {
            # 注释/白名单
            'comment': re.compile(r'^\s*[#!]'),
            'whitelist': re.compile(r'^\s*@@'),
            # 各规则格式
            'adguard': re.compile(r'^\|\|([^\^\/\*:]+)\^?'),
            'adblock': re.compile(r'^\|\|?([^\s\^\/\*:]+)\^?'),
            'hosts': re.compile(r'^\s*(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)'),
            'domain': re.compile(r'^([^\s#]+)$')
        }

    def should_skip(self, line):
        """判断是否跳过处理"""
        line = line.strip()
        return (
            not line
            or self.rule_formats['comment'].match(line)
            or self.rule_formats['whitelist'].match(line)
        )

    async def resolve_with_fallback(self, domain, max_retries=2):
        """三级DNS解析策略"""
        domain = domain.lower().strip()
        if not domain or '.' not in domain:
            return False
            
        # 清理特殊字符
        clean_domain = re.sub(r'[^\w.-]', '', domain.split('$')[0].split('^')[0])
        if not clean_domain:
            return False
            
        # 检查缓存
        if clean_domain in self.cache:
            return self.cache[clean_domain]
            
        # 智能选择解析组
        resolver_group = 'cn' if clean_domain.endswith('.cn') else 'intl'
        
        for attempt in range(max_retries):
            for resolver in self.resolver_groups[resolver_group] + self.resolver_groups['backup']:
                try:
                    result = await asyncio.wait_for(
                        resolver.query(clean_domain, 'A'),
                        timeout=2 if resolver_group == 'cn' else 3
                    )
                    if result:
                        self.cache[clean_domain] = True
                        return True
                except Exception:
                    continue
                    
            # 失败后切换解析组
            resolver_group = 'backup' if resolver_group != 'backup' else 'intl'
            
        self.cache[clean_domain] = False
        return False

async def process_file(input_path, output_path):
    """处理规则文件"""
    validator = RuleValidator()
    kept_lines = []
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            raw_line = line.strip()
            if validator.should_skip(raw_line):
                kept_lines.append(line.rstrip('\n'))
                continue
                
            # 尝试匹配所有规则格式
            domain = None
            for fmt in ['adguard', 'adblock', 'hosts', 'domain']:
                if match := validator.rule_formats[fmt].search(raw_line):
                    domain = match.group(1)
                    break
                    
            # hosts格式直接放行
            if fmt == 'hosts' and domain:
                kept_lines.append(line.rstrip('\n'))
                continue
                
            # 需要验证的域名
            if domain and await validator.resolve_with_fallback(domain):
                kept_lines.append(line.rstrip('\n'))
    
    # 保持原始换行符
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(kept_lines))

async def main():
    print("🌍 启动全球DNS规则处理器...")
    start_time = time.time()
    
    try:
        # 处理所有规则文件
        for rule_type in ['adblock', 'allow', 'hosts']:
            for input_file in Path(INPUT_DIR).glob(f"{rule_type}*.txt"):
                output_file = Path(OUTPUT_DIR) / input_file.name
                await process_file(input_file, output_file)
                print(f"🔄 已处理: {input_file.name}")
                
    except Exception as e:
        print(f"💥 处理失败: {str(e)}")
        raise
    
    print(f"✅ 全部完成! 耗时: {time.time()-start_time:.2f}秒")

if __name__ == "__main__":
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()