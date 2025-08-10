#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions优化版AdBlock规则处理器 - 修复括号匹配问题
"""

import re
from pathlib import Path
from typing import Set, List, Tuple
import sys
import resource

# 设置内存软限制为512MB
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, -1))

def memory_guard():
    """内存监控装饰器"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except MemoryError:
                print("⚠️ 内存不足，启用分块处理模式")
                return chunked_processing(*args, **kwargs)
        return wrapper
    return decorator

@memory_guard()
def load_rules(filepath: Path) -> Tuple[Set[str], List[str]]:
    """安全加载规则文件"""
    encodings = ('utf-8', 'latin-1')
    for enc in encodings:
        try:
            with open(filepath, 'r', encoding=enc) as f:
                white_set = set()
                original_lines = []
                for i, line in enumerate(f):
                    if i % 10000 == 0 and i > 0:  # 每1万行检查内存
                        check_memory()
                    line = line.strip()
                    if not line or line.startswith(('!', '#')):
                        continue
                    norm = normalize_rule(line)
                    white_set.add(norm)
                    original_lines.append(line)
                return white_set, original_lines
        except UnicodeDecodeError:
            continue
    raise ValueError(f"无法解码文件: {filepath}")

def normalize_rule(rule: str) -> str:
    """GitHub Actions专用轻量标准化"""
    rule = rule.split('$', 1)[0]  # 先分割提高性能
    if rule.startswith('@@'):
        rule = rule[2:]
    elif rule.startswith('||'):
        rule = rule[2:]
    return rule.replace('*', '').strip('.').lower()

def check_memory():
    """监控内存使用"""
    used = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024
    if used > 450:  # MB
        raise MemoryError()

def chunked_processing(black_file: Path, white_set: Set[str], chunk_size=50000) -> List[str]:
    """分块处理超大规模文件"""
    results = []
    encodings = ('utf-8', 'latin-1')
    
    for enc in encodings:
        try:
            with open(black_file, 'r', encoding=enc) as f:
                chunk = []
                for i, line in enumerate(f):
                    if i % chunk_size == 0 and i > 0:
                        results.extend(process_chunk(chunk, white_set))
                        chunk = []
                        check_memory()
                    chunk.append(line)
                if chunk:
                    results.extend(process_chunk(chunk, white_set))
            return results
        except UnicodeDecodeError:
            continue
    raise ValueError(f"无法解码文件: {black_file}")

def process_chunk(chunk: List[str], white_set: Set[str]) -> List[str]:
    """处理单个数据块"""
    return [
        line.strip() for line in chunk 
        if line.strip() and 
        (line.startswith(('!', '#')) or 
         (not is_covered(normalize_rule(line), white_set)))
    ]

def is_covered(normalized_black: str, white_set: Set[str]) -> bool:
    """优化后的覆盖检查"""
    if normalized_black in white_set:
        return True
    # 检查子域名覆盖（最多3级）
    parts = normalized_black.split('.')
    max_level = min(3, len(parts) - 1)
    for i in range(1, max_level + 1):
        if '.'.join(parts[i:]) in white_set:
            return True
    return False

def main():
    rules_dir = Path('data/rules')
    print("::group::🚀 开始处理规则")
    
    try:
        print("正在加载白名单...")
        white_set, _ = load_rules(rules_dir / 'allow.txt')
        
        print("过滤黑名单规则...")
        filtered = chunked_processing(rules_dir / 'dns.txt', white_set)
        
        print("写入结果文件...")
        with open(rules_dir / 'adblock-filtered.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(filtered))
            
        print(f"::notice title=完成::处理完毕！保留规则: {len(filtered)}条")
        print("::endgroup::")
        sys.exit(0)
    except Exception as e:
        print(f"::error::处理失败: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()