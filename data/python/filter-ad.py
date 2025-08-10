#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AdGuard Home 规则处理器 - GitHub Actions 生产版
功能：用白名单净化黑名单 | 环境适配 | 完整统计
"""

import re
from pathlib import Path
from typing import Set, Dict
import sys
import resource
import os
from datetime import datetime

# 环境初始化配置
def setup_github_actions():
    """GitHub Actions 专用环境优化"""
    # 内存限制（保留 20% 缓冲）
    mem_total = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    resource.setrlimit(resource.RLIMIT_AS, (int(mem_total * 0.8), mem_total))
    
    # 文件描述符限制（处理大文件必需）
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
    
    # 禁用 SWAP（防止 CI 环境性能抖动）
    if hasattr(resource, 'RLIMIT_SWAP'):
        resource.setrlimit(resource.RLIMIT_SWAP, (0, 0))

class AdGuardProcessor:
    def __init__(self):
        setup_github_actions()
        self.stats = {
            'start_time': datetime.utcnow(),
            'whitelist_rules': 0,
            'blacklist_input': 0,
            'blacklist_output': 0,
            'memory_peak_mb': 0,
            'time_elapsed_sec': 0
        }
        # 预编译 AdGuard 专用正则
        self.rule_normalizer = re.compile(r'^(@@)?(\|\|)?([^*^|~#]+)')

    def _update_memory_stats(self):
        """记录内存峰值"""
        current_mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        self.stats['memory_peak_mb'] = max(self.stats['memory_peak_mb'], current_mem)
        if current_mem > 3500:  # GitHub Actions 默认内存限制为 4GB
            raise MemoryError(f"内存使用超过安全阈值: {current_mem:.1f}MB")

    def load_whitelist(self, path: Path) -> Set[str]:
        """加载白名单并统计"""
        whitelist = set()
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(('!', '#')):
                    norm = self._normalize_rule(line)
                    if norm:
                        whitelist.add(norm)
                        self.stats['whitelist_rules'] += 1
                        if self.stats['whitelist_rules'] % 2000 == 0:
                            self._update_memory_stats()
        return whitelist

    def _normalize_rule(self, rule: str) -> str:
        """AdGuard 规则标准化（严格模式）"""
        match = self.rule_normalizer.match(rule.split('$')[0].strip())
        if not match:
            return ""
        domain = match.group(3).lower().strip('^|~#')
        return domain.strip('.') if domain else ""

    def process_blacklist(self, black_path: Path, white_path: Path, output_path: Path):
        """核心处理流程"""
        whitelist = self.load_whitelist(white_path)
        
        with open(black_path, 'r', encoding='utf-8') as infile, \
             open(output_path, 'w', encoding='utf-8') as outfile:
            
            for line in infile:
                line = line.strip()
                self.stats['blacklist_input'] += 1
                
                # 保留注释和空行
                if not line or line.startswith(('!', '#')):
                    outfile.write(f"{line}\n")
                    continue
                
                # 白名单过滤
                if self._normalize_rule(line) not in whitelist:
                    outfile.write(f"{line}\n")
                    self.stats['blacklist_output'] += 1
                
                # 进度监控
                if self.stats['blacklist_input'] % 10000 == 0:
                    print(
                        f"⏳ 进度: {self.stats['blacklist_input']:,} 行 | "
                        f"保留: {self.stats['blacklist_output']:,} 规则 | "
                        f"内存: {self.stats['memory_peak_mb']:.1f}MB",
                        flush=True
                    )
                    self._update_memory_stats()
        
        # 最终统计
        self.stats['time_elapsed_sec'] = (datetime.utcnow() - self.stats['start_time']).total_seconds()

    def generate_report(self) -> str:
        """生成 GitHub Actions 友好报告"""
        return f"""
::group::📈 规则处理统计摘要
🕒 耗时: {self.stats['time_elapsed_sec']:.2f} 秒
📊 内存峰值: {self.stats['memory_peak_mb']:.1f} MB
⚪ 白名单规则: {self.stats['whitelist_rules']:,}
⚫ 输入黑名单: {self.stats['blacklist_input']:,}
🟢 输出黑名单: {self.stats['blacklist_output']:,}
🔴 过滤规则: {self.stats['blacklist_input'] - self.stats['blacklist_output']:,}
::endgroup::
"""

def main():
    try:
        processor = AdGuardProcessor()
        
        # 文件路径（硬编码确保可靠性）
        input_dir = Path('data/rules')
        processor.process_blacklist(
            black_path=input_dir / 'dns.txt',
            white_path=input_dir / 'allow.txt',
            output_path=input_dir / 'adblock-filtered.txt'
        )
        
        # 打印统计报告
        print(processor.generate_report())
        sys.exit(0)
    except Exception as e:
        print(f"::error::🚨 处理失败: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()