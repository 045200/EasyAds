#!/usr/bin/env python3
"""
规则合并与处理脚本
功能：
1. 合并多个广告拦截规则文件
2. 合并多个白名单规则文件
3. 清理注释和空行
4. 分离白名单规则
5. 规则去重排序
6. 最终文件输出
"""

import os
import re
from pathlib import Path

def merge_files(file_pattern: str, output_file: str, clean_comments: bool = True) -> None:
    """合并匹配模式的文件并清理注释"""
    file_list = glob.glob(file_pattern)
    if not file_list:
        print(f"警告: 没有找到匹配 {file_pattern} 的文件")
        return

    # 合并文件内容
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in file_list:
            with open(file, 'r', encoding='utf-8') as infile:
                outfile.write(infile.read())
                outfile.write('\n')

    # 清理注释
    if clean_comments:
        with open(output_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # 移除注释行 (! 或 # 开头但不是 ## 的行)
        content = re.sub(r'^[!].*$\n', '', content, flags=re.MULTILINE)
        content = re.sub(r'^#(?!\s*#).*\n?', '', content, flags=re.MULTILINE)
        
        # 移除连续空行
        content = re.sub(r'\n{3,}', '\n\n', content)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(content.strip())

def filter_allow_rules(combined_file: str, allow_file: str) -> None:
    """从合并文件中过滤出白名单规则"""
    with open(combined_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    with open(allow_file, 'w', encoding='utf-8') as f:
        for line in lines:
            if line.startswith('@@'):
                f.write(line)

def deduplicate_file(file_path: str) -> None:
    """对文件内容进行去重和排序"""
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 去重并排序
    unique_lines = sorted(set(lines), key=lambda x: x.lower())
    
    # 写入临时文件
    temp_file = f"temp_{os.path.basename(file_path)}"
    with open(temp_file, 'w', encoding='utf-8') as f:
        f.writelines(unique_lines)
    
    # 替换原文件
    os.replace(temp_file, file_path)

def main():
    # 初始化工作目录
    os.chdir('tmp')
    print("当前工作目录:", os.getcwd())

    # 1. 合并广告拦截规则
    print("合并上游拦截规则...")
    merge_files('adblock*.txt', 'combined_adblock.txt')
    print("拦截规则合并完成")

    # 2. 合并白名单规则
    print("合并上游白名单规则...")
    merge_files('allow*.txt', 'combined_allow.txt')
    print("白名单规则合并完成")

    # 3. 过滤白名单规则
    print("过滤白名单规则...")
    filter_allow_rules('combined_allow.txt', 'allow.txt')
    print("白名单规则过滤完成")

    # 4. 准备输出目录
    target_dir = Path('../data/rules')
    target_dir.mkdir(parents=True, exist_ok=True)

    # 5. 移动并重命名文件
    print("整理输出文件...")
    files_to_move = {
        'combined_adblock.txt': target_dir / 'adblock.txt',
        'allow.txt': target_dir / 'allow.txt'
    }

    for src, dst in files_to_move.items():
        if os.path.exists(src):
            os.replace(src, dst)
            print(f"已移动 {src} -> {dst}")

    # 6. 去重处理
    print("规则去重中...")
    os.chdir(target_dir)
    for file in Path('.').glob('*.txt'):
        print(f"正在处理 {file.name}...")
        deduplicate_file(file.name)
    print("规则去重完成")

if __name__ == '__main__':
    import glob  # 移动到文件顶部会更规范，这里为了保持原有结构
    main()