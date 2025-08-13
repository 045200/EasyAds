import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 折中方案核心匹配规则（黑白名单同步优化）
ALLOW_PATTERN = re.compile(
    r'^@@\|\|[\w.-]+\^?(\$~?[\w,=-]+)?|'  # 域名规则+基础修饰符
    r'^@@##.+|'                           # 元素隐藏例外
    r'^@@/[^/]+/|'                        # 正则例外
    r'^@@\d+\.\d+\.\d+\.\d+'              # IP例外
)

BLOCK_PATTERN = re.compile(
    r'^\|\|[\w.-]+\^(\$~?[\w,=-]+)?|'     # 域名规则+基础修饰符
    r'^/[\w/-]+/|'                        # 正则规则
    r'^##.+|'                             # 元素隐藏
    r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+'      # Hosts格式
)

def clean_rules(content, pattern):
    """通用规则清理函数"""
    # 移除注释行（保留空行用于分隔）
    content = re.sub(r'^[!#].*$\n', '', content, flags=re.MULTILINE)
    # 按模式过滤有效规则
    return '\n'.join(line for line in content.splitlines() if pattern.search(line))

print("合并拦截规则")
with open('combined_adblock.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('adblock*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            outfile.write(infile.read() + '\n')

# 黑名单折中处理
with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
    f.write(clean_rules(open('combined_adblock.txt').read(), BLOCK_PATTERN))

print("合并白名单规则")
with open('combined_allow.txt', 'w', encoding='utf-8') as outfile:
    for file in glob.glob('allow*.txt'):
        with open(file, 'r', encoding='utf-8', errors='ignore') as infile:
            outfile.write(infile.read() + '\n')

# 白名单折中处理
with open('cleaned_allow.txt', 'w', encoding='utf-8') as f:
    f.write(clean_rules(open('combined_allow.txt').read(), ALLOW_PATTERN))

print("生成最终规则")
with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
    f.write('\n' + open('cleaned_allow.txt').read())

# 提取白名单时仍保持简单判断
with open('allow.txt', 'w', encoding='utf-8') as f:
    f.writelines(line for line in open('cleaned_adblock.txt') 
              if line.startswith('@@'))

# 文件移动和去重（保持不变）
target_dir = Path('../data/rules/')
target_dir.mkdir(exist_ok=True)
Path('cleaned_adblock.txt').rename(target_dir / 'adblock.txt')
Path('allow.txt').rename(target_dir / 'allow.txt')

print("规则去重")
for file in glob.glob(str(target_dir / '*.txt')):
    with open(file, 'r+', encoding='utf-8') as f:
        lines = sorted({line for line in f if line.strip()}, key=str.lower)
        f.seek(0)
        f.writelines(lines)
        f.truncate()

print("处理完成")