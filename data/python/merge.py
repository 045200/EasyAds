import os
import glob
import re
from pathlib import Path

os.chdir('tmp')

# 黑名单规则特征
BLOCK_PATTERNS = r'^\|\|[\w.-]+\^|^/[\w/-]+/|^##[^#]+|^\d+\.\d+\.\d+\.\d+\s+[\w.-]+|^[\w.-]+\s+[\w.-]+$|^\|\|[\w.-]+\^\$[^=]+|^#@?#'

# 白名单规则特征
ALLOW_PATTERNS = r'^@@\|\|[\w.-]+\^?|^@@/[^/]+/|^@@##[^#]+|^\|\|[\w.-]+\^\$removeparam|^@@\d+\.\d+\.\d+\.\d+|^@@\s*[\w.-]+$|^\s*!.*@@\s*[\w.-]+|^\d+\.\d+\.\d+\.\d+\s+@@'

print("合并上游拦截规则")
file_list = glob.glob('adblock*.txt')
with open('combined_adblock.txt', 'w') as outfile:
    for file in file_list:
        with open(file, 'r') as infile:
            outfile.write(infile.read())
            outfile.write('\n')

with open('combined_adblock.txt', 'r') as f:
    content = f.read()
# 清理黑名单规则
content = re.sub(r'^[!].*$\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^#(?!\s*#).*\n?', '', content, flags=re.MULTILINE)
content = re.sub(fr'^(?!(?:{BLOCK_PATTERNS})).*$\n?', '', content, flags=re.MULTILINE)

with open('cleaned_adblock.txt', 'w') as f:
    f.write(content)
print("拦截规则合并完成")

print("合并上游白名单规则")
allow_file_list = glob.glob('allow*.txt')
with open('combined_allow.txt', 'w') as outfile:
    for file in allow_file_list:
        with open(file, 'r') as infile:
            outfile.write(infile.read())
            outfile.write('\n')

with open('combined_allow.txt', 'r') as f:
    content = f.read()
# 清理白名单规则
content = re.sub(r'^[!].*$\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^#(?!\s*#).*\n?', '', content, flags=re.MULTILINE)
content = re.sub(fr'^(?!(?:{ALLOW_PATTERNS})).*$\n?', '', content, flags=re.MULTILINE)

with open('cleaned_allow.txt', 'w') as f:
    f.write(content)
print("白名单规则合并完成")

print("过滤白名单规则")
with open('cleaned_allow.txt', 'r') as f:
    allow_lines = [line for line in f if re.match(ALLOW_PATTERNS, line)]

with open('cleaned_adblock.txt', 'a') as outfile:
    outfile.writelines(allow_lines)

with open('cleaned_adblock.txt', 'r') as f:
    lines = f.readlines()
with open('allow.txt', 'w') as f:
    f.writelines(line for line in lines if re.match(ALLOW_PATTERNS, line))

# 移动文件到目标目录
target_dir = Path('../data/rules/')
target_dir.mkdir(parents=True, exist_ok=True)
Path('cleaned_adblock.txt').rename(target_dir / 'adblock.txt')
Path('allow.txt').rename(target_dir / 'allow.txt')

print("规则去重中")
os.chdir(target_dir)
for file in glob.glob('*.txt'):
    with open(file, 'r', encoding='utf8') as f:
        lines = list(set(f.readlines()))
    lines.sort()
    with open(file, 'w', encoding='utf8') as f:
        f.writelines(lines)
print("规则去重完成")