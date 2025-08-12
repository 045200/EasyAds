#!/usr/bin/env python3
import os
import re
import glob
import subprocess
import itertools
from pathlib import Path

def clean_rules(content):
    """
    增强型规则清理（严格分离白名单和拦截规则）
    保留类型：
    - 白名单规则 @@
    - 域名规则 ||...^
    - 元素隐藏规则 ##
    - 修饰符规则 $...
    - 精确匹配规则 =...
    """
    # 第一阶段：提取所有明确的白名单规则
    allow_rules = set()
    other_rules = []
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        
        # 捕获所有白名单规则（包括复杂修饰符）
        if line.startswith('@@'):
            allow_rules.add(line)
            continue
            
        # 转换hosts格式规则
        if re.match(r'^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+', line):
            domain = re.sub(r'^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+).*$', r'||\2^', line)
            other_rules.append(domain)
        # 保留其他有效规则
        elif re.match(r'^(\|\||##|#@#|=|\$)', line):
            other_rules.append(line)
    
    return list(allow_rules), other_rules

def resolve_conflicts(allow_rules, block_rules):
    """
    冲突解决：白名单优先于拦截规则
    返回：（最终允许规则，最终拦截规则）
    """
    # 建立域名到规则的映射（用于冲突检测）
    allow_domains = set()
    block_map = {}
    
    # 提取白名单域名主体（不含修饰符）
    for rule in allow_rules:
        domain = re.sub(r'^@@\|\|([^\^\/]+).*$', r'\1', rule)
        allow_domains.add(domain)
    
    # 过滤被白名单覆盖的拦截规则
    filtered_block = []
    for rule in block_rules:
        if rule.startswith('||'):
            domain = re.sub(r'^\|\|([^\^\/]+).*$', r'\1', rule)
            if domain not in allow_domains:
                filtered_block.append(rule)
        else:
            filtered_block.append(rule)
    
    return list(allow_rules), filtered_block

def chunked_read(file_path, chunk_size=50000):
    """ 内存友好的分块读取生成器 """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        while True:
            chunk = list(itertools.islice(f, chunk_size))
            if not chunk:
                break
            yield chunk

def merge_files(file_pattern, output_file):
    """ 流式合并文件 """
    file_list = sorted(glob.glob(file_pattern))
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in file_list:
            for chunk in chunked_read(file):
                outfile.writelines(chunk)
            outfile.write('\n')

def deduplicate_file(file_path):
    """ CI优化的去重+排序 """
    temp_file = f"{file_path}.tmp"
    
    # 使用系统sort工具（内存效率更高）
    try:
        subprocess.run(
            f"sort -u {file_path} -o {temp_file}",
            shell=True,
            check=True,
            stderr=subprocess.PIPE
        )
        os.replace(temp_file, file_path)
    except subprocess.CalledProcessError as e:
        print(f"::error::排序失败: {e.stderr.decode().strip()}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        raise

def main():
    print("::group::规则处理流程启动")
    
    # 准备工作目录
    os.makedirs('tmp', exist_ok=True)
    os.chdir('tmp')
    
    # 合并源文件
    print("合并拦截规则...")
    merge_files('adblock*.txt', 'combined_adblock.txt')
    print("合并白名单规则...")
    merge_files('allow*.txt', 'combined_allow.txt')
    
    # 处理混合规则
    print("清理和冲突解决...")
    with open('combined_adblock.txt', 'r', encoding='utf-8') as f:
        allow_rules, block_rules = clean_rules(f.read())
    
    # 合并独立白名单文件
    with open('combined_allow.txt', 'r', encoding='utf-8') as f:
        extra_allow, _ = clean_rules(f.read())
        allow_rules.extend(extra_allow)
    
    # 冲突解决
    final_allow, final_block = resolve_conflicts(allow_rules, block_rules)
    
    # 保存最终文件
    print("生成最终规则文件...")
    target_dir = Path('../data/rules')
    target_dir.mkdir(exist_ok=True)
    
    with open(target_dir/'adblock.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_allow + final_block))
    
    with open(target_dir/'allow.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_allow))
    
    # 去重处理
    print("去重和排序...")
    os.chdir(target_dir)
    for f in glob.glob('*.txt'):
        deduplicate_file(f)
    
    # 验证统计
    allow_count = sum(1 for _ in open('allow.txt', 'r'))
    block_count = sum(1 for _ in open('adblock.txt', 'r')) - allow_count
    print(f"::notice::规则统计 白名单: {allow_count}条 | 拦截: {block_count}条")
    print("::endgroup::")

if __name__ == '__main__':
    main()