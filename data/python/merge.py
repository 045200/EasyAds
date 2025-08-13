import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 合并文件函数（自动处理编码问题）
def merge_files(pattern, output_file):
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in glob.glob(pattern):
            try:
                with open(file, 'r', encoding='utf-8') as infile:
                    outfile.write(infile.read() + '\n')
            except UnicodeDecodeError:
                with open(file, 'r', encoding='gbk') as infile:
                    outfile.write(infile.read() + '\n')

# 规则清理函数（整合特征匹配）
def clean_rules(input_file, output_file, is_allow=False):
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 黑白名单特征直接内联到re.sub
    if is_allow:
        content = re.sub(
            r'^[!#].*$[\n\r]|^(?!@@\|\|[\w.-]+\^?|@@/[^/]+/|@@##[^#]+|\|\|[\w.-]+\^\$removeparam|@@\d+\.\d+\.\d+\.\d+|@@\s*[\w.-]+$|\s*!.*@@\s*[\w.-]+|\d+\.\d+\.\d+\.\d+\s+@@).*$[\n\r]',
            '', 
            content, 
            flags=re.MULTILINE
        )
    else:
        content = re.sub(
            r'^[!#].*$[\n\r]|^(?!\|\|[\w.-]+\^|/[\w/-]+/|##[^#]+|\d+\.\d+\.\d+\.\d+\s+[\w.-]+|[\w.-]+\s+[\w.-]+$|\|\|[\w.-]+\^\$[^=]+|#@?#).*$[\n\r]',
            '', 
            content, 
            flags=re.MULTILINE
        )
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

print("合并上游拦截规则")
merge_files('adblock*.txt', 'combined_adblock.txt')
clean_rules('combined_adblock.txt', 'cleaned_adblock.txt', is_allow=False)

print("合并上游白名单规则")
merge_files('allow*.txt', 'combined_allow.txt')
clean_rules('combined_allow.txt', 'cleaned_allow.txt', is_allow=True)

print("合并最终规则")
with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
    with open('cleaned_allow.txt', 'r', encoding='utf-8') as a:
        f.write('\n' + a.read())

print("提取纯白名单")
with open('cleaned_adblock.txt', 'r', encoding='utf-8') as f:
    allow_lines = [line for line in f if re.match(
        r'^@@\|\|[\w.-]+\^?|^@@/[^/]+/|^@@##[^#]+|^\|\|[\w.-]+\^\$removeparam|^@@\d+\.\d+\.\d+\.\d+|^@@\s*[\w.-]+$|^\s*!.*@@\s*[\w.-]+|^\d+\.\d+\.\d+\.\d+\s+@@',
        line
    )]
with open('allow.txt', 'w', encoding='utf-8') as f:
    f.writelines(allow_lines)

# 移动文件到目标目录
target_dir = Path('../data/rules/')
target_dir.mkdir(exist_ok=True)
Path('cleaned_adblock.txt').rename(target_dir / 'adblock.txt')
Path('allow.txt').rename(target_dir / 'allow.txt')

print("规则去重")
for rule_file in (target_dir / 'adblock.txt', target_dir / 'allow.txt'):
    if rule_file.exists():
        with open(rule_file, 'r+', encoding='utf-8') as f:
            lines = sorted(set(f.readlines()), key=lambda x: x.lower())
            f.seek(0)
            f.writelines(lines)
            f.truncate()

print("处理完成")