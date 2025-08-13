#!/usr/bin/env python3
"""
多语法规则处理器（GitHub Action兼容版）
特性：
1. 完整保留GitHub风格的多规则语法识别（ABP/Hosts/Regex）
2. 独立处理黑白名单去重
3. 兼容原始文件目录结构
"""

import re
import os
from pathlib import Path
from typing import Set, Dict, Generator
from dataclasses import dataclass
import hashlib

# 输入输出配置（与原始脚本完全一致）
INPUT_DIR = Path('tmp')
OUTPUT_DIR = Path('data/rules')
ADBLOCK_PATTERN = 'adblock*.txt'
ALLOW_PATTERN = 'allow*.txt'

class RuleParser:
    """GitHub风格多规则解析器（完整保留原特性）"""
    
    # 预编译规则类型识别正则 [citation:1]
    RULE_PATTERNS = {
        'ABP': re.compile(r'^\|\|([^\s\\\/]+)\^?\$?\b'),
        'HOSTS': re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::)\s+([\w.-]+)'),
        'REGEX': re.compile(r'^/(.+)/[gimsuy]*$'),
        'COMMENT': re.compile(r'^[![]')
    }
    
    @classmethod
    def classify(cls, line: str) -> str:
        """规则类型检测（增强版）[citation:1]"""
        line = line.strip()
        if not line:
            return 'COMMENT'
        
        for rule_type, pattern in cls.RULE_PATTERNS.items():
            if pattern.match(line):
                return rule_type
        return 'ABP'  # 默认按ABP规则处理

    @classmethod
    def normalize(cls, line: str) -> str:
        """规则标准化转换（保留所有语法特性）[citation:1][citation:7]"""
        rule_type = cls.classify(line)
        
        # 保留原始规则（特殊标记不转换）
        if rule_type in ('ABP', 'REGEX', 'COMMENT'):
            return line
        
        # 仅Hosts规则转换
        if rule_type == 'HOSTS':
            if match := cls.RULE_PATTERNS['HOSTS'].match(line):
                return f"||{match.group(1)}^"
        
        return line

@dataclass
class RuleSets:
    """分类型规则容器（增强去重控制）"""
    black: Set[str]
    white: Set[str]

class AdvancedRuleProcessor:
    def __init__(self):
        # 独立去重池（增强版哈希算法）[citation:3]
        self._seen_hashes = {
            'black': set(),  # 黑名单去重池
            'white': set()   # 白名单去重池
        }

    def _process_line(self, line: str) -> tuple[str, bool]:
        """增强型行处理（保留所有语法特性）"""
        raw_line = line.strip()
        if RuleParser.classify(raw_line) == 'COMMENT':
            return None, False

        # 标准化处理（保留原始ABP/Regex规则）
        processed = RuleParser.normalize(raw_line)
        is_allow = raw_line.startswith('@@')
        
        # 分类型去重（基于标准化后的规则）[citation:3]
        rule_hash = hashlib.sha256(processed.lower().encode()).hexdigest()
        pool = 'white' if is_allow else 'black'
        
        if rule_hash in self._seen_hashes[pool]:
            return None, False
        
        self._seen_hashes[pool].add(rule_hash)
        return processed, is_allow

    def process_files(self) -> RuleSets:
        """处理流程（兼容原始文件结构）"""
        rules = RuleSets(black=set(), white=set())

        # 合并处理黑名单文件（支持多语法）
        for file in INPUT_DIR.glob(ADBLOCK_PATTERN):
            with open(file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    rule, is_allow = self._process_line(line)
                    if rule and not is_allow:
                        rules.black.add(rule)

        # 单独处理白名单文件（严格@@检测）
        for file in INPUT_DIR.glob(ALLOW_PATTERN):
            with open(file, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    rule, is_allow = self._process_line(line)
                    if rule and is_allow:
                        rules.white.add(rule)

        return rules

    @staticmethod
    def _write_output(rules: RuleSets):
        """保持原始输出结构（增强排序）[citation:2]"""
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # 黑名单输出（保留所有语法）
        with open(OUTPUT_DIR / 'adblock.txt', 'w', encoding='utf-8') as f:
            f.writelines(f"{r}\n" for r in sorted(rules.black, key=lambda x: (len(x), x.lower())))

        # 白名单输出（严格@@开头）
        with open(OUTPUT_DIR / 'allow.txt', 'w', encoding='utf-8') as f:
            f.writelines(f"{r}\n" for r in sorted(rules.white, key=lambda x: (len(x), x.lower())))

def main():
    print("=" * 40)
    print("多语法规则处理开始".center(40))
    print("=" * 40)

    processor = AdvancedRuleProcessor()
    rules = processor.process_files()
    processor._write_output(rules)

    print(f"生成黑名单规则: {len(rules.black)} 条（支持ABP/Hosts/Regex语法）")
    print(f"生成白名单规则: {len(rules.white)} 条（严格@@开头）")
    print("=" * 40)
    print("处理完成".center(40))
    print("=" * 40)

if __name__ == '__main__':
    INPUT_DIR.mkdir(exist_ok=True)
    main()