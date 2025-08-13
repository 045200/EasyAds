#!/usr/bin/env python3
"""
终极规则分类器（严格分离黑白名单）
功能：
1. 白名单处理：仅提取@@规则和特殊放行格式，跳过所有黑名单规则
2. 黑名单处理：仅提取非@@规则，跳过所有白名单规则
3. 不保留任何注释或元数据
"""

import re
from pathlib import Path
from typing import Set
import hashlib

# 配置
INPUT_DIR = Path('input_rules')
OUTPUT_DIR = Path('processed_rules')
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

class RuleFilter:
    """严格规则过滤器"""
    
    # 白名单规则匹配（核心检测逻辑）
    @staticmethod
    def is_allow_rule(line: str) -> bool:
        line = line.strip()
        return (
            line.startswith('@@') or                  # 标准@@规则
            re.match(r'^\d+\.\d+\.\d+\.\d+\s+@@', line) or  # Hosts放行格式
            re.match(r'^@@\d+\.\d+\.\d+\.\d+', line)       # IP放行格式
        ) and not line.startswith('!')               # 排除注释
    
    # 黑名单规则匹配（排除白名单后）
    @staticmethod
    def is_block_rule(line: str) -> bool:
        line = line.strip()
        return (
            not line.startswith(('!', '@@')) and     # 非注释且非白名单
            bool(re.match(r'^(\|\||\d+\.|##|/)', line))  # 匹配ABP/Hosts/元素隐藏/正则

class RuleProcessor:
    def __init__(self):
        self.allow_rules: Set[str] = set()
        self.block_rules: Set[str] = set()
        self.allow_hashes: Set[str] = set()
        self.block_hashes: Set[str] = set()
    
    def _hash_rule(self, rule: str) -> str:
        """生成规则哈希（白名单区分大小写）"""
        return hashlib.sha256(rule.encode()).hexdigest()
    
    def process_file(self, file_path: Path):
        """处理单个文件"""
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('!'):
                    continue  # 跳过空行和注释
                
                # 白名单处理（严格模式）
                if RuleFilter.is_allow_rule(line):
                    rule_hash = self._hash_rule(line)
                    if rule_hash not in self.allow_hashes:
                        self.allow_hashes.add(rule_hash)
                        self.allow_rules.add(line)
                    continue
                
                # 黑名单处理（排除白名单后）
                if RuleFilter.is_block_rule(line):
                    # 转换Hosts规则为ABP格式
                    if line.startswith(('0.0.0.0', '127.0.0.1', '::')):
                        if domain := re.match(r'^(?:\d+\.\d+\.\d+\.\d+|::)\s+([\w.-]+)', line):
                            line = f"||{domain.group(1)}^"
                    
                    rule_hash = self._hash_rule(line.lower())  # 黑名单不区分大小写
                    if rule_hash not in self.block_hashes:
                        self.block_hashes.add(rule_hash)
                        self.block_rules.add(line)
    
    def process_all(self):
        """处理所有规则文件"""
        for file in INPUT_DIR.glob('*.txt'):
            self.process_file(file)
        
        # 保存结果
        with open(OUTPUT_DIR / 'allow.txt', 'w') as f:
            f.write("\n".join(sorted(self.allow_rules)))
        
        with open(OUTPUT_DIR / 'block.txt', 'w') as f:
            f.write("\n".join(sorted(self.block_rules)))
        
        print(f"处理完成：白名单{len(self.allow_rules)}条 | 黑名单{len(self.block_rules)}条")

if __name__ == '__main__':
    print("=== 规则分类处理器 ===")
    print("模式：严格分离黑白名单 | 不保留注释")
    
    processor = RuleProcessor()
    processor.process_all()
    
    print(f"输出文件：{OUTPUT_DIR}/allow.txt 和 block.txt")