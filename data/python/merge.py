import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 完整AdGuard语法匹配规则
FULL_SYNTAX = re.compile(
    r'^(\|\|)?[\w.-]+\^?(\$[\w,=-]+)?$|'          # 基础域名规则
    r'^@@(\|\|)?[\w.-]+\^?(\$[\w,=-]+)?$|'        # 例外规则
    r'^/[\w\W]+/$|^@@/[\w\W]+/$|'                # 正则规则
    r'^##.+$|^@@##.+$|'                          # 元素隐藏规则
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$|'           # Hosts格式
    r'^\|\|[\w.-]+\^\$dnstype=\w+$|'             # DNS类型规则
    r'^@@\|\|[\w.-]+\^\$dnstype=\w+$|'           # DNS例外
    r'^\|\|[\w.-]+\^\$dnsrewrite=\w+$|'          # DNS重写
    r'^@@\|\|[\w.-]+\^\$dnsrewrite=NOERROR$'     # DNS重写例外
)

def clean_rules(content):
    """高效规则清理函数（保留全语法）"""
    return '\n'.join(
        line.strip() for line in content.splitlines() 
        if line.strip() and FULL_SYNTAX.match(line.strip())
    )

def merge_files(pattern, output_file):
    """合并文件并清理规则"""
    with open(output_file, 'w', encoding='utf-8') as out:
        for file in glob.glob(pattern):
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                cleaned = clean_rules(f.read())
                if cleaned:
                    out.write(cleaned + '\n')

def deduplicate(filepath):
    """高效去重（保留顺序）"""
    with open(filepath, 'r+', encoding='utf-8') as f:
        seen = set()
        unique_lines = []
        for line in f:
            lower_line = line.lower()
            if lower_line not in seen:
                seen.add(lower_line)
                unique_lines.append(line)
        f.seek(0)
        f.writelines(unique_lines)
        f.truncate()

# 处理拦截规则
merge_files('adblock*.txt', 'adblock.txt')

# 处理白名单规则
merge_files('allow*.txt', 'allow.txt')

# 移动文件到目标目录
target_dir = Path('../')
target_dir.mkdir(exist_ok=True)
Path('adblock.txt').rename(target_dir / 'adblock.txt')
Path('allow.txt').rename(target_dir / 'allow.txt')

# 去重处理
for file in [target_dir / 'adblock.txt', target_dir / 'allow.txt']:
    deduplicate(file)

print("规则处理完成")