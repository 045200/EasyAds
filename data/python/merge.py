import os
import glob
import re
from pathlib import Path

def is_allow_rule(line):
    """判断是否为白名单规则（@@开头的例外规则）
    支持的格式：
    - 标准域名放行：@@||example.com^
    - 正则放行：@@/ads?banner/
    - 元素隐藏例外：@@##.ad-container
    - 参数移除例外：@@||example.com^$removeparam=test
    - IP地址放行：@@127.0.0.1
    - 带修饰符的放行：@@||ads.com^$script,document
    - 注释中的放行规则：! comment @@example.com
    """
    allow_patterns = [
        r'^@@\|\|[\w.-]+\^[\w]*$',       # 标准域名放行（可选后缀）
        r'^@@/[^/]+/',                  # 正则表达式放行
        r'^@@##[^#]+',                  # 元素隐藏例外
        r'^@@\|\|[\w.-]+\^\$removeparam=[^\s]+', # 参数移除例外
        r'^@@\d+\.\d+\.\d+\.\d+',       # IP地址放行
        r'^@@\|\|[\w.-]+\^\$[^\s,]+(?:,[^\s]+)*$', # 带修饰符的放行
        r'^\s*!.*@@\s*[\w.-]+',         # 注释中的放行规则
        r'^@@\$\S+',                    # 特殊修饰符放行
        r'^@@\|\|.*?\^~?\S+'            # 宽松域名匹配（含~排除）
    ]
    return any(re.match(p, line.strip()) for p in allow_patterns)

def is_block_rule(line):
    """判断是否为拦截规则（非@@开头且符合拦截语法）
    支持的格式：
    - 域名拦截：||ads.example.com^
    - 正则拦截：/ads?banner/
    - 元素隐藏：##.ad-container
    - Hosts格式：127.0.0.1 ads.com
    - 带修饰符拦截：||ads.com^$script,domain=example.com
    - 参数移除：||example.com^$removeparam=test
    - 特殊类型拦截：$script, $image等
    """
    line = line.strip()
    if line.startswith('@@'):  # 排除白名单规则
        return False
        
    block_patterns = [
        r'^\|\|[\w.-]+\^[\w]*$',        # 标准域名拦截
        r'^/[\w/-]+/',                  # 正则表达式拦截
        r'^##[^#]+',                    # 元素隐藏规则
        r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+', # Hosts格式拦截
        r'^\|\|[\w.-]+\^\$[^\s,]+(?:,[^\s]+)*$', # 带修饰符拦截
        r'^\$\S+',                      # 网络请求修饰符
        r'^[\w.-]+\s+[\w.-]+$',         # 简化Hosts格式
        r'^#@?#',                       # 元素隐藏例外标记
        r'^\|\|.*?\^\$removeparam=[^\s]+' # 参数移除
    ]
    return any(re.match(p, line) for p in block_patterns)

def clean_comments(content):
    """清除注释和空行（保留规则中的#字符）"""
    # 移除!开头的整行注释
    content = re.sub(r'^![^\n]*\n', '', content, flags=re.MULTILINE)
    # 移除#开头但不含##的注释（保留元素隐藏规则）
    content = re.sub(r'^#(?!##)[^\n]*\n', '', content, flags=re.MULTILINE)
    # 移除行尾注释（保留规则中的$字符）
    content = re.sub(r'\s+![^\n]*$', '', content, flags=re.MULTILINE)
    return content

def process_rules(input_file, output_file, rule_type):
    """处理规则文件并保留指定类型规则"""
    with open(input_file, 'r', encoding='utf-8') as f:
        content = clean_comments(f.read())
    
    lines = content.splitlines()
    processed = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if rule_type == 'allow' and is_allow_rule(line):
            processed.append(line)
        elif rule_type == 'block' and is_block_rule(line):
            processed.append(line)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(processed) + '\n')

def merge_files(file_pattern, output_file):
    """合并多个同类型规则文件"""
    file_list = glob.glob(file_pattern)
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in file_list:
            with open(file, 'r', encoding='utf-8') as infile:
                outfile.write(infile.read().strip() + '\n\n')

def deduplicate_file(file_path):
    """文件去重（保持原有顺序）"""
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    seen = set()
    unique_lines = []
    for line in lines:
        clean_line = line.strip()
        if clean_line and clean_line not in seen:
            seen.add(clean_line)
            unique_lines.append(line)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(unique_lines)

def main():
    # 确保工作目录存在
    os.makedirs('tmp', exist_ok=True)
    os.chdir('tmp')
    
    print("1. 合并拦截规则...")
    merge_files('adblock*.txt', 'combined_adblock.txt')
    process_rules('combined_adblock.txt', 'cleaned_adblock.txt', 'block')
    
    print("2. 合并白名单规则...")
    merge_files('allow*.txt', 'combined_allow.txt') 
    process_rules('combined_allow.txt', 'cleaned_allow.txt', 'allow')
    
    print("3. 合并最终规则集...")
    with open('cleaned_allow.txt', 'r', encoding='utf-8') as f:
        allow_rules = f.read()
    
    with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
        f.write('\n' + allow_rules)
    
    print("4. 提取独立白名单文件...")
    with open('cleaned_adblock.txt', 'r', encoding='utf-8') as f:
        all_rules = f.readlines()
    
    with open('allow.txt', 'w', encoding='utf-8') as f:
        for line in all_rules:
            if is_allow_rule(line.strip()):
                f.write(line)

    print("5. 移动文件到目标目录...")
    target_dir = Path('../data/rules')
    target_dir.mkdir(parents=True, exist_ok=True)
    
    Path('cleaned_adblock.txt').rename(target_dir / 'adblock.txt')
    Path('allow.txt').rename(target_dir / 'allow.txt')

    print("6. 规则去重...")
    os.chdir(target_dir)
    for file in ['adblock.txt', 'allow.txt']:
        deduplicate_file(file)
    
    print("处理完成！规则文件保存在：", target_dir.resolve())

if __name__ == '__main__':
    main()