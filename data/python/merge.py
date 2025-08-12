#!/usr/bin/env python3
import os
import re
import glob
import subprocess
import itertools
from pathlib import Path

def clean_rules(content, rule_type):
    """
    根据规则类型独立清理规则
    rule_type: 'allow' 或 'block'
    """
    cleaned_rules = set()
    
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        
        if rule_type == 'allow':
            # 只处理白名单规则
            if line.startswith('@@'):
                cleaned_rules.add(line)
            # 转换hosts格式的白名单
            elif re.match(r'^\s*0\.0\.0\.0\s+', line) and '# whitelist' in line.lower():
                domain = re.sub(r'^\s*0\.0\.0\.0\s+([^\s#]+).*$', r'@@||\1^', line)
                cleaned_rules.add(domain)
        else:
            # 处理黑名单规则
            if line.startswith('||') or line.startswith('##') or line.startswith('=') or line.startswith('$'):
                cleaned_rules.add(line)
            # 转换hosts格式的黑名单
            elif re.match(r'^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+', line):
                domain = re.sub(r'^\s*(0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+).*$', r'||\2^', line)
                cleaned_rules.add(domain)
    
    return list(cleaned_rules)

def chunked_read(file_path, chunk_size=50000):
    """ 内存友好的分块读取生成器 """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        while True:
            chunk = list(itertools.islice(f, chunk_size))
            if not chunk:
                break
            yield chunk

def merge_files(file_pattern, output_file, rule_type):
    """ 流式合并文件并根据类型处理 """
    file_list = sorted(glob.glob(file_pattern))
    combined_rules = set()
    
    for file in file_list:
        for chunk in chunked_read(file):
            content = ''.join(chunk)
            rules = clean_rules(content, rule_type)
            combined_rules.update(rules)
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write('\n'.join(sorted(combined_rules)))

def deduplicate_file(file_path):
    """ CI优化的去重+排序 """
    temp_file = f"{file_path}.tmp"
    
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
    
    # 独立处理白名单规则
    print("处理白名单文件...")
    merge_files('allow*.txt', 'pure_allow.txt', 'allow')
    
    # 独立处理黑名单规则
    print("处理黑名单文件...")
    merge_files('adblock*.txt', 'pure_block.txt', 'block')
    
    # 保存最终文件
    print("生成最终规则文件...")
    target_dir = Path('../data/rules')
    target_dir.mkdir(exist_ok=True)
    
    # 生成纯白名单文件
    with open('pure_allow.txt', 'r', encoding='utf-8') as f_allow, \
         open(target_dir/'allow.txt', 'w', encoding='utf-8') as f_out:
        f_out.write(f_allow.read())
    
    # 生成合并文件（白名单在前）
    with open('pure_allow.txt', 'r', encoding='utf-8') as f_allow, \
         open('pure_block.txt', 'r', encoding='utf-8') as f_block, \
         open(target_dir/'adblock.txt', 'w', encoding='utf-8') as f_out:
        
        f_out.write(f_allow.read())
        f_out.write('\n')
        f_out.write(f_block.read())
    
    # 去重处理
    print("去重和排序...")
    os.chdir(target_dir)
    deduplicate_file('allow.txt')
    deduplicate_file('adblock.txt')
    
    # 验证统计
    allow_count = sum(1 for _ in open('allow.txt', 'r'))
    block_count = sum(1 for _ in open('adblock.txt', 'r')) - allow_count
    print(f"::notice::规则统计 白名单: {allow_count}条 | 拦截: {block_count}条")
    print("::endgroup::")

if __name__ == '__main__':
    main()