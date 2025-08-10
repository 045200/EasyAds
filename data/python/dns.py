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

class DomainValidator:
    def __init__(self):
        uvloop.install()
        self.loop = asyncio.get_event_loop()
        
        # 完整的全球DNS解析组（国内+国外）
        self.resolvers = [
            # 国内DNS
            aiodns.DNSResolver(nameservers=['223.5.5.5'], loop=self.loop, timeout=2),    # 阿里
            aiodns.DNSResolver(nameservers=['119.29.29.29'], loop=self.loop, timeout=2), # 腾讯
            aiodns.DNSResolver(nameservers=['114.114.114.114'], loop=self.loop, timeout=2), # 114
            # 国外DNS
            aiodns.DNSResolver(nameservers=['8.8.8.8'], loop=self.loop, timeout=3),      # Google
            aiodns.DNSResolver(nameservers=['1.1.1.1'], loop=self.loop, timeout=3),     # Cloudflare
            aiodns.DNSResolver(nameservers=['9.9.9.9'], loop=self.loop, timeout=3)      # Quad9
        ]
        self.cache = {}
        self.comment_prefixes = ('#', '!')
        self.whitelist_prefix = '@@'

    def should_skip(self, line):
        """判断是否跳过处理（注释/空行/白名单）"""
        line = line.strip()
        return (
            not line 
            or any(line.startswith(p) for p in self.comment_prefixes)
            or line.startswith(self.whitelist_prefix)
        )

    async def resolve_domain(self, domain):
        """全球DNS解析（自动适应国内外域名）"""
        try:
            if not domain or '.' not in domain:
                return False
                
            # 清理规则修饰符
            clean_domain = re.sub(r'[\^\|\*\$\s]', '', domain.split('$')[0])
            if not clean_domain:
                return False
                
            # 检查缓存
            if clean_domain in self.cache:
                return self.cache[clean_domain]
                
            # 根据域名类型选择超时（国内域名快速失败）
            timeout = 2 if re.search(r'\.(cn|com|net)$', clean_domain) else 3
            
            # 并行查询所有DNS
            tasks = [asyncio.create_task(r.query(clean_domain, 'A')) for r in self.resolvers]
            done, _ = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            
            for task in done:
                if result := task.result():
                    self.cache[clean_domain] = True
                    return True
                    
            self.cache[clean_domain] = False
            return False
            
        except Exception as e:
            print(f"解析失败 {domain}: {str(e)}")
            return False

async def process_file(input_path, output_path):
    """处理规则文件"""
    validator = DomainValidator()
    kept_rules = []
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            
            # 保留注释/空行/白名单
            if validator.should_skip(line):
                kept_rules.append(line)
                continue
                
            # 提取域名核心部分
            domain = None
            for pattern in [
                r'^\|\|([^\^\/\*]+)\^',  # ||example.com^
                r'^([^\s\^\/\*]+)',      # example.com
                r'^0\.0\.0\.0\s+([^\s]+)' # 0.0.0.0 example.com
            ]:
                if match := re.search(pattern, line):
                    domain = match.group(1)
                    break
                    
            # 有效域名才进行解析
            if domain and await validator.resolve_domain(domain):
                kept_rules.append(line)
    
    # 保持文件原始格式
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(kept_rules))

async def main():
    print("🌐 开始处理全球域名规则...")
    start_time = time.time()
    
    try:
        # 处理所有规则文件
        for rule_type in ['adblock', 'allow']:
            for input_file in Path(INPUT_DIR).glob(f"{rule_type}*.txt"):
                output_file = Path(OUTPUT_DIR) / input_file.name
                await process_file(input_file, output_file)
                print(f"✅ 已处理: {input_file.name}")
                
    except Exception as e:
        print(f"❌ 处理失败: {str(e)}")
        raise
    
    print(f"⏱️ 处理完成! 总耗时: {time.time()-start_time:.2f}秒")

if __name__ == "__main__":
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()