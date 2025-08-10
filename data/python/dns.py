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
        
        # 优化的DNS服务器配置
        self.resolvers = [
            aiodns.DNSResolver(nameservers=['223.5.5.5'], loop=self.loop, timeout=2),  # 阿里DNS
            aiodns.DNSResolver(nameservers=['119.29.29.29'], loop=self.loop, timeout=2) # 腾讯DNS
        ]
        self.cache = {}
        self.skip_prefixes = ('#', '!', '@@', '||', '0.0.0.0')

    def is_comment_or_special(self, line):
        """判断是否是注释或特殊规则"""
        line = line.strip()
        return any(line.startswith(prefix) for prefix in self.skip_prefixes) or not line

    async def safe_resolve(self, domain):
        """安全的域名解析"""
        try:
            if not domain or self.is_comment_or_special(domain):
                return False
                
            # 清理域名中的特殊字符
            clean_domain = re.sub(r'[^a-zA-Z0-9.-]', '', domain.split('$')[0].split('^')[0])
            if not clean_domain or '.' not in clean_domain:
                return False
                
            # 检查缓存
            if clean_domain in self.cache:
                return self.cache[clean_domain]
                
            # 并行查询所有DNS服务器
            tasks = [asyncio.create_task(r.query(clean_domain, 'A')) for r in self.resolvers]
            done, _ = await asyncio.wait(tasks, timeout=2, return_when=asyncio.FIRST_COMPLETED)
            
            for task in done:
                if result := task.result():
                    self.cache[clean_domain] = True
                    return True
                    
            self.cache[clean_domain] = False
            return False
            
        except Exception:
            return False

async def process_rules(input_path, output_path):
    """处理规则文件"""
    validator = DomainValidator()
    valid_rules = []
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or validator.is_comment_or_special(line):
                valid_rules.append(line)
                continue
                
            # 尝试提取域名
            domain = None
            for pattern in [
                r'^\|\|([^\^\/\*]+)\^',  # ||example.com^
                r'^([^\s\^\/\*]+)\^',    # example.com^
                r'^0\.0\.0\.0\s+([^\s]+)' # 0.0.0.0 example.com
            ]:
                if match := re.search(pattern, line):
                    domain = match.group(1)
                    break
                    
            if domain and await validator.safe_resolve(domain):
                valid_rules.append(line)
    
    # 保留原始文件格式
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(valid_rules))

async def main():
    print("🚀 开始处理广告规则...")
    start_time = time.time()
    
    try:
        for rule_type in ['adblock', 'allow']:
            for input_file in Path(INPUT_DIR).glob(f"{rule_type}*.txt"):
                output_file = Path(OUTPUT_DIR) / input_file.name
                await process_rules(input_file, output_file)
                print(f"✅ 已处理: {input_file.name}")
                
    except Exception as e:
        print(f"❌ 处理失败: {str(e)}")
        raise
    
    print(f"⏱️ 处理完成! 耗时: {time.time()-start_time:.2f}秒")

if __name__ == "__main__":
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    finally:
        loop.close()