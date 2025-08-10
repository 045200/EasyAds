#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home规则GitHub Actions处理器 - 生产级
"""

import re
from pathlib import Path
from typing import Set, Dict
import sys
import resource
import os
from datetime import datetime

# GitHub Actions环境优化
def setup_environment():
    """严格的CI环境配置"""
    # 内存限制（保留15%缓冲）
    mem_limit = int(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') * 0.85)
    resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
    
    # 文件描述符限制提升
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
    
    # 设置UTC时区（CI环境统一）
    os.environ['TZ'] = 'UTC'

class RuleProcessor:
    """20万+规则处理核心"""
    
    def __init__(self):
        setup_environment()
        self.whitelist = set()
        self.stats = {
            'start_time': datetime.utcnow(),
            'whitelist_loaded': 0,
            'blacklist_processed': 0,
            'rules_kept': 0,
            'memory_peak': 0
        }
        
        # 预编译正则（AdGuard DNS语法专用）
        self.rule_parser = re.compile(
            r'^(@@\|\|)?(\|\|)?([a-z0-9-*]+\.?)+(\^|\$|/)'
        )

    def _memory_check(self):
        """每处理1万条检查内存"""
        self.stats['memory_peak'] = max(
            self.stats['memory_peak'],
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024
        )
        if self.stats['memory_peak'] > 3800:  # GitHub Actions的4GB内存限制
            raise MemoryError("内存使用接近CI环境上限")

    def load_whitelist(self, path: Path):
        """加载1万+白名单规则"""
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(('!', '#')):
                    norm = self._normalize_rule(line)
                    if norm:
                        self.whitelist.add(norm)
                        self.stats['whitelist_loaded'] += 1
                        if self.stats['whitelist_loaded'] % 2000 == 0:
                            self._memory_check()

    def _normalize_rule(self, rule: str) -> str:
        """AdGuard规则标准化（性能优化版）"""
        match = self.rule_parser.match(rule.split('$')[0].strip())
        if not match:
            return ""
        domain = match.group(0)
        return domain.replace('^', '').replace('*', '').strip('.|/').lower()

    def process_blacklist(self, input_path: Path, output_path: Path):
        """处理20万+黑名单"""
        with open(input_path, 'r', encoding='utf-8') as infile, \
             open(output_path, 'w', encoding='utf-8') as outfile:
            
            for line in infile:
                line = line.strip()
                self.stats['blacklist_processed'] += 1
                
                # 保留注释和空行
                if not line or line.startswith(('!', '#')):
                    outfile.write(f"{line}\n")
                    continue
                
                # 规则过滤
                if not self._is_whitelisted(line):
                    outfile.write(f"{line}\n")
                    self.stats['rules_kept'] += 1
                
                # 进度报告
                if self.stats['blacklist_processed'] % 10000 == 0:
                    print(
                        f"⏳ 已处理: {self.stats['blacklist_processed']:,} | "
                        f"保留: {self.stats['rules_kept']:,} | "
                        f"内存: {self.stats['memory_peak']:.1f}MB",
                        flush=True
                    )
                    self._memory_check()

    def _is_whitelisted(self, rule: str) -> bool:
        """白名单检查（优化版）"""
        norm = self._normalize_rule(rule)
        if not norm:
            return False
        
        # 直接匹配
        if norm in self.whitelist:
            return True
        
        # 子域名检查（最多4级）
        parts = norm.split('.')
        for i in range(1, min(5, len(parts))):
            if '.'.join(parts[i:]) in self.whitelist:
                return True
        return False

    def generate_report(self):
        """生成GitHub Actions友好报告"""
        duration = (datetime.utcnow() - self.stats['start_time']).total_seconds()
        
        report = [
            "::group::📊 处理结果统计",
            f"🕒 耗时: {duration:.2f}秒",
            f"📈 内存峰值: {self.stats['memory_peak']:.1f}MB",
            f"⚪ 白名单规则: {self.stats['whitelist_loaded']:,}",
            f"⚫ 原始黑名单: {self.stats['blacklist_processed']:,}",
            f"🟢 保留规则: {self.stats['rules_kept']:,}",
            f"🔴 过滤规则: {self.stats['blacklist_processed'] - self.stats['rules_kept']:,}",
            "::endgroup::"
        ]
        
        return "\n".join(report)

def main():
    try:
        processor = RuleProcessor()
        
        # 输入输出路径（硬编码确保可靠）
        input_dir = Path('data/rules')
        processor.load_whitelist(input_dir / 'allow.txt')
        processor.process_blacklist(
            input_dir / 'dns.txt',
            input_dir / 'adblock-filtered.txt'
        )
        
        # 生成报告
        print(processor.generate_report())
        sys.exit(0)
    except Exception as e:
        print(f"::error::❌ 处理失败: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()