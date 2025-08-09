#!/usr/bin/env python3
import re
import time
import sqlite3
import tldextract
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置常量
CONFIG = {
    'input_dir': Path('tmp'),
    'cache_db': Path('tmp/dns_cache.db'),
    'timeout': 2,                # 单次查询超时
    'batch_size': 500,           # 每批处理量
    'max_workers': 3,            # 并发控制
    'cache_ttl': 86400 * 7,      # 7天缓存有效期
    'dns_servers': {
        'domestic': ['223.5.5.5', '119.29.29.29', '114.114.114.114'],
        'overseas': ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    },
    'cn_tlds': {'cn', '中国', '公司', '网络', 'gov.cn', 'edu.cn', 'org.cn'},
    'whitelist': {               # 已知有效直接放行的域名
        'baidu.com', 'qq.com', 'taobao.com' 
    }
}

class DNSValidator:
    def __init__(self):
        self.tld_extract = tldextract.TLDExtract(cache_dir='/tmp/tldcache')
        self._init_cache()
        self.stats = {'total': 0, 'cached': 0, 'checked': 0, 'removed': 0}

    def _init_cache(self):
        """初始化缓存数据库"""
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    valid_domestic INTEGER,  -- 国内DNS是否可解析
                    valid_overseas INTEGER,  -- 国外DNS是否可解析
                    checked_at INTEGER,
                    expires_at INTEGER
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain)')

    def _clean_cache(self):
        """清理过期缓存"""
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            conn.execute('DELETE FROM domains WHERE expires_at < ?', (int(time.time()),))

    def validate_domain(self, domain):
        """验证单个域名的有效性（国内外DNS）"""
        if domain in CONFIG['whitelist']:
            return True  # 白名单直接通过
        
        # 检查缓存
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            row = conn.execute(
                'SELECT valid_domestic, valid_overseas FROM domains WHERE domain=? AND expires_at>=?',
                (domain, int(time.time()))
            ).fetchone()
            
            if row:
                self.stats['cached'] += 1
                return any(row)  # 只要任一组DNS能解析就保留

        # 实际检查
        self.stats['checked'] += 1
        domestic_ok = self._check_with_servers(domain, CONFIG['dns_servers']['domestic'])
        overseas_ok = self._check_with_servers(domain, CONFIG['dns_servers']['overseas'])
        
        # 更新缓存
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO domains VALUES (?, ?, ?, ?, ?)',
                (domain, int(domestic_ok), int(overseas_ok), 
                int(time.time()), int(time.time()) + CONFIG['cache_ttl'])
            )
        
        return domestic_ok or overseas_ok

    def _check_with_servers(self, domain, servers):
        """使用指定DNS服务器组检查域名"""
        with ThreadPoolExecutor(max_workers=min(3, CONFIG['max_workers'])) as executor:
            futures = [executor.submit(self._dig_query, domain, server) for server in servers]
            for future in as_completed(futures, timeout=CONFIG['timeout']*3):
                if future.result():
                    return True
        return False

    def _dig_query(self, domain, server):
        """执行dig查询"""
        try:
            cmd = ['dig', f'@{server}', domain, 'A', '+short', '+time=1', '+tries=1']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            return bool(result.stdout.strip())
        except:
            return False

    def _extract_domain(self, rule):
        """从规则中提取纯净域名"""
        # 处理广告规则语法
        rule = re.sub(r'^\|\|', '', rule)       # 去掉开头的||
        rule = re.sub(r'\^.*$', '', rule)       # 去掉^后面的部分
        rule = re.sub(r'\$.*$', '', rule)       # 去掉$后面的部分
        return rule.split('/')[0].lower()       # 去掉路径部分并转小写

    def process_file(self, file):
        """处理单个规则文件"""
        print(f"🔍 Processing {file.name}...")
        tmp_file = file.with_suffix('.tmp')
        
        with open(file, 'r', encoding='utf-8', errors='ignore') as fin:
            lines = fin.readlines()
        
        valid_lines = []
        batch = []
        
        for line in lines:
            line = line.strip()
            if not line or line[0] in ('!', '#', '@'):
                valid_lines.append(line)
                continue
            
            domain = self._extract_domain(line)
            if not re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', domain):
                valid_lines.append(line)
                continue
            
            self.stats['total'] += 1
            batch.append((line, domain))
            
            # 批量处理
            if len(batch) >= CONFIG['batch_size']:
                self._process_batch(batch, valid_lines)
                batch = []
        
        # 处理剩余批次
        if batch:
            self._process_batch(batch, valid_lines)
        
        # 写入临时文件
        with open(tmp_file, 'w', encoding='utf-8') as fout:
            fout.write('\n'.join(valid_lines) + '\n')
        
        # 替换原文件
        tmp_file.replace(file)
        
        # 打印统计信息
        removed = self.stats['total'] - len([l for l in valid_lines if l and l[0] not in ('!', '#', '@')])
        print(f"✅ Finished {file.name}")
        print(f"   Total rules: {self.stats['total']} | Removed: {removed}")
        print(f"   Cache hits: {self.stats['cached']} | Fresh checks: {self.stats['checked']}")

    def _process_batch(self, batch, valid_lines):
        """处理一批规则"""
        domains = [item[1] for item in batch]
        with ThreadPoolExecutor(max_workers=CONFIG['max_workers'])) as executor:
            # 并行验证域名
            results = list(executor.map(self.validate_domain, domains))
        
        # 保留有效的规则
        for (line, _), is_valid in zip(batch, results):
            if is_valid:
                valid_lines.append(line)

def main():
    validator = DNSValidator()
    
    # 清理过期缓存
    validator._clean_cache()
    
    # 处理所有规则文件
    for file in CONFIG['input_dir'].glob('*.txt'):
        validator.process_file(file)
        
        # 重置统计计数
        validator.stats = {'total': 0, 'cached': 0, 'checked': 0, 'removed': 0}

if __name__ == '__main__':
    main()