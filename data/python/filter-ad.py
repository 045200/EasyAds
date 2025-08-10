import re
from pathlib import Path

def normalize_rule(rule):
    """标准化规则以便比较：移除特殊字符和域名标记"""
    # 移除例外标记(@@)
    if rule.startswith('@@'):
        rule = rule[2:]
    
    # 移除$及后面的选项参数
    rule = rule.split('$', 1)[0]
    
    # 移除域名通配符(||)
    if rule.startswith('||'):
        rule = rule[2:]
    
    # 移除首尾的管道符(|)
    rule = rule.removeprefix('|').removesuffix('|')
    
    # 移除通配符(*)
    rule = rule.replace('*', '')
    
    # 移除首尾的点号并转为小写
    return rule.strip('.').lower()

def is_rule_covered(black_rule, white_rules):
    """检查黑名单规则是否被任何白名单规则覆盖"""
    normalized_black = normalize_rule(black_rule)
    
    for white_rule in white_rules:
        normalized_white = normalize_rule(white_rule)
        
        # 完全匹配
        if normalized_black == normalized_white:
            return True
            
        # 白名单规则更通用(域名vs子域名)
        if normalized_white and f".{normalized_black}".endswith(f".{normalized_white}"):
            return True
            
        # 白名单规则更通用(路径)
        if normalized_white in normalized_black and normalized_white.count('/') < normalized_black.count('/'):
            return True
    
    return False

def filter_blocked_rules(adblock_file, allow_file, output_file):
    """过滤掉被白名单覆盖的黑名单规则"""
    # 读取白名单规则
    try:
        with open(allow_file, 'r', encoding='utf-8') as f:
            white_rules = [line.strip() for line in f if line.strip() and not line.startswith('!')]
    except UnicodeDecodeError:
        with open(allow_file, 'r', encoding='latin-1') as f:
            white_rules = [line.strip() for line in f if line.strip() and not line.startswith('!')]
    
    # 读取黑名单规则
    try:
        with open(adblock_file, 'r', encoding='utf-8') as f:
            black_lines = [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        with open(adblock_file, 'r', encoding='latin-1') as f:
            black_lines = [line.strip() for line in f if line.strip()]
    
    # 过滤规则
    filtered_rules = []
    for rule in black_lines:
        # 保留注释行和空行
        if not rule or rule.startswith('!') or rule.startswith('#'):
            filtered_rules.append(rule)
            continue
            
        # 检查该黑名单规则是否被白名单覆盖
        if not is_rule_covered(rule, white_rules):
            filtered_rules.append(rule)
    
    # 写入过滤后的规则
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(filtered_rules) + '\n')

def main():
    rules_dir = Path('data/rules')
    
    print("根据白名单过滤黑名单规则...")
    filter_blocked_rules(
        rules_dir / 'adblock.txt',
        rules_dir / 'allow.txt',
        rules_dir / 'adblock-filtered.txt'  # 输出到新文件，不覆盖原文件
    )
    
    print("过滤完成，结果保存在:")
    print(f"  - {rules_dir / 'adblock-filtered.txt'}")
    print(f"  - {rules_dir / 'allow.txt'} (未修改)")

if __name__ == '__main__':
    main()