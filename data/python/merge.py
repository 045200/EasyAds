#!/usr/bin/env python3
"""
AdBlock规则合并与优化脚本
功能：合并多个规则文件，标准化格式，高效去重
"""

import os
import glob
import re
from pathlib import Path
from collections import OrderedDict
from itertools import islice
import argparse

# 常量定义
MAX_CHUNK_SIZE = 50000  # 分块处理的行数
VALID_RULE_PATTERNS = [
    r'^\|\|', r'^@@\|\|', r'^##', r'^#@#', 
    r'^\$', r'^=', r'^\/.+\/', r'^\s*\['
]

def is_valid_rule(line: str) -> bool:
    """检查是否为有效的AdBlock规则"""
    line = line.strip()
    if not line or line.startswith('!'):
        return False
    return any(re.match(p, line) for p in VALID_RULE_PATTERNS)

def standardize_rule(line: str) -> str:
    """标准化规则格式"""
    # 转换hosts格式
    line = re.sub(r'^\s*0\.0\.0\.0\s+([^\s#]+)', r'||\1^', line)
    line = re.sub(r'^\s*127\.0\.0\.1\s+([^\s#]+)', r'||\1^', line)
    return line

def stream_process_file(input_path: str, output_path: str):
    """
    流式处理文件：
    1. 跳过注释和无效行
    2. 标准化规则格式
    """
    with open(input_path, 'r', encoding='utf-8') as infile, \
         open(output_path, 'w', encoding='utf-8') as outfile:
        
        for line in infile:
            if is_valid_rule(line):
                standardized = standardize_rule(line)
                if standardized:
                    outfile.write(standardized + '\n')

def merge_files(file_patterns: list, output_file: str):
    """合并多个文件到单个输出文件"""
    seen = set()
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for pattern in file_patterns:
            for file in glob.glob(pattern):
                with open(file, 'r', encoding='utf-8') as infile:
                    for line in infile:
                        if line.strip() and line not in seen:
                            seen.add(line)
                            outfile.write(line)

def chunked_deduplicate(input_path: str):
    """
    分块去重算法：
    1. 按大块读取文件避免内存不足
    2. 使用OrderedDict保持顺序去重
    """
    temp_files = []
    temp_dir = "temp_chunks"
    os.makedirs(temp_dir, exist_ok=True)

    # 第一阶段：分块去重
    with open(input_path, 'r', encoding='utf-8') as f:
        for i, chunk in enumerate(iter(lambda: list(islice(f, MAX_CHUNK_SIZE)), [])):
            unique_chunk = list(OrderedDict.fromkeys(chunk))
            temp_file = os.path.join(temp_dir, f'chunk_{i}.tmp')
            with open(temp_file, 'w', encoding='utf-8') as tf:
                tf.writelines(unique_chunk)
            temp_files.append(temp_file)

    # 第二阶段：合并临时文件
    with open(input_path, 'w', encoding='utf-8') as final:
        for temp_file in temp_files:
            with open(temp_file, 'r', encoding='utf-8') as tf:
                final.writelines(tf)
            os.remove(temp_file)
    os.rmdir(temp_dir)

def process_rules(input_dir: str, output_dir: str):
    """主处理流程"""
    os.chdir(input_dir)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # 合并并处理黑名单
    print("处理黑名单规则...")
    merge_files(['adblock*.txt', 'ad*.txt'], 'combined_adblock.txt')
    stream_process_file('combined_adblock.txt', 'cleaned_adblock.txt')
    chunked_deduplicate('cleaned_adblock.txt')

    # 处理白名单
    print("处理白名单规则...")
    merge_files(['allow*.txt', 'white*.txt'], 'combined_allow.txt')
    stream_process_file('combined_allow.txt', 'cleaned_allow.txt')

    # 提取白名单规则 (@@)
    with open('cleaned_allow.txt', 'r', encoding='utf-8') as f:
        allow_rules = [line for line in f if line.startswith('@@')]
    
    # 生成最终文件
    print("生成最终规则集...")
    with open(os.path.join(output_dir, 'adblock.txt'), 'w', encoding='utf-8') as f:
        # 合并黑名单+白名单
        with open('cleaned_adblock.txt', 'r', encoding='utf-8') as cb:
            f.writelines(cb)
        f.writelines(allow_rules)
    
    with open(os.path.join(output_dir, 'allow.txt'), 'w', encoding='utf-8') as f:
        f.writelines(allow_rules)

    # 最终去重
    for filename in ['adblock.txt', 'allow.txt']:
        chunked_deduplicate(os.path.join(output_dir, filename))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='tmp', help='输入目录')
    parser.add_argument('--output', default='data/rules', help='输出目录')
    args = parser.parse_args()

    print(f"开始处理规则文件（输入目录：{args.input}）")
    process_rules(args.input, args.output)
    print(f"规则处理完成，输出到：{args.output}")

if __name__ == '__main__':
    main()