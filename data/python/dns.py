#!/usr/bin/env python3
import re
import time
import sqlite3
import tldextract
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# 常量定义
CONFIG = {
    'input_dir': Path('tmp'),
    'cache_db': Path('tmp/dns_cache.db'),
    'timeout': 2,
    'workers': 6,
    'dns_groups': {
        'domestic': ['223.5.5.5', '119.29.29.29', '114.114.114.114'],
        'overseas': ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    },
    'cn_tlds': {'cn', '中国', '公司', '网络', 'gov.cn', 'edu.cn', 'org.cn'}
}

class DNSChecker:
    def __init__(self):
        self.tld_extract = tldextract.TLDExtract(cache_dir='/tmp/tldcache')
        self._init_cache()

    def _init_cache(self):
        """带类型标记的缓存表"""
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    type TEXT CHECK(type IN ('domestic', 'overseas')),
                    valid INTEGER,
                    checked_at INTEGER
                )
            ''')

    def check(self, domain):
        """动态智能检查入口"""
        domain_type = self._classify(domain)
        
        # 检查缓存
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            res = conn.execute(
                'SELECT valid FROM domains WHERE domain=? AND type=?',
                (domain, domain_type)
            ).fetchone()
            if res:
                return bool(res[0])

        # 动态解析
        if domain_type == 'domestic':
            servers = CONFIG['dns_groups']['domestic']
        else:
            servers = CONFIG['dns_groups']['overseas']
        
        valid = self._check_servers(domain, servers)
        
        # 更新缓存
        with sqlite3.connect(CONFIG['cache_db']) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO domains VALUES (?, ?, ?, ?)',
                (domain, domain_type, int(valid), int(time.time()))
        
        return valid

    def _classify(self, domain):
        """域名分类核心逻辑"""
        ext = self.tld_extract(domain)
        if ext.suffix in CONFIG['cn_tlds']:
            return 'domestic'
        return 'overseas'

    def _check_servers(self, domain, servers):
        """严格3服务器检查"""
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self._query, domain, s) for s in servers]
            return any(f.result() for f in as_completed(futures, timeout=CONFIG['timeout']*3))

    def _query(self, domain, server):
        """单服务器查询"""
        try:
            cmd = ['dig', f'@{server}', domain, 'A', '+short', f'+time={CONFIG["timeout"]}']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=CONFIG['timeout'])
            return bool(result.stdout.strip())
        except:
            return False

def main():
    checker = DNSChecker()
    
    for file in CONFIG['input_dir'].glob('*.txt'):
        print(f"Processing {file.name}")
        tmp_file = file.with_suffix('.tmp')
        
        with open(file, 'r', encoding='utf-8', errors='ignore') as fin, \
             open(tmp_file, 'w', encoding='utf-8') as fout:
            
            for line in fin:
                line = line.strip()
                if not line or line[0] in ('!', '#', '@'):
                    fout.write(line + '\n')
                    continue
                
                domain = re.sub(r'^\|\||\^|\$.*$', '', line).split('/')[0]
                if re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', domain):
                    if checker.check(domain.lower()):
                        fout.write(line + '\n')
        
        tmp_file.replace(file)

if __name__ == '__main__':
    main()