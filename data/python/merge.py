import re
import sys
from pathlib import Path
from typing import Set, List, Tuple
from datetime import datetime, timezone

def print_progress(message: str):
    """实时进度输出"""
    print(f"  → {message}", file=sys.stderr)

def print_rejection(line_num: int, reason: str, rule: str):
    """实时显示被拒绝的规则"""
    print(f"  × [L{line_num}] {reason}: {rule[:60]}{'...' if len(rule)>60 else ''}", file=sys.stderr)

def is_valid_rule(rule: str) -> Tuple[bool, str]:
    """
    增强规则验证，返回(是否有效, 原因)
    """
    if not rule or rule.isspace():
        return False, "空规则"
    if rule.startswith('!'):
        return False, "注释"
    if '##' in rule or '#@#' in rule:
        return False, "元素隐藏规则"
    if rule.startswith(('#?#', '$$')):
        return False, "脚本注入规则"
    
    # 允许的规则模式
    if re.match(r'^(\|\||/|\*|[a-zA-Z0-9_.-]|@@|\$).*', rule):
        return True, ""
    
    return False, "无效格式"

def process_rules(input_file: Path) -> Tuple[Set[str], Set[str]]:
    """
    核心处理函数，返回(拦截规则集, 放行规则集)
    """
    block_rules = set()
    allow_rules = set()
    total_lines = 0

    print_progress(f"开始处理文件: {input_file.name}")
    
    # 自动检测编码
    encodings = ['utf-8', 'latin-1', 'gbk']
    for enc in encodings:
        try:
            content = input_file.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        print_progress("错误：无法解码文件编码")
        return block_rules, allow_rules

    lines = content.splitlines()
    print_progress(f"读取到 {len(lines)} 行原始数据")

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        total_lines += 1

        # 跳过空行和章节标题
        if not line or line.startswith('['):
            continue

        # 转换hosts格式规则
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+', line):
            parts = line.split()
            if len(parts) > 1 and re.match(r'^[a-zA-Z0-9_.-]+$', parts[1]):
                block_rules.add(f"||{parts[1]}^")
                continue
            else:
                print_rejection(line_num, "无效hosts规则", raw_line)
                continue

        # 移除行内注释
        clean_line = re.sub(r'\s*#.*$', '', line).strip()
        if not clean_line:
            continue

        # 规则分类处理
        is_allow = clean_line.startswith('@@')
        rule_part = clean_line[2:] if is_allow else clean_line

        valid, reason = is_valid_rule(rule_part)
        if valid:
            if is_allow:
                allow_rules.add(clean_line)
            else:
                block_rules.add(clean_line)
        else:
            print_rejection(line_num, reason, raw_line)

    print_progress(f"处理完成 | 拦截: {len(block_rules)} | 放行: {len(allow_rules)} | 丢弃: {total_lines - len(block_rules) - len(allow_rules)}")
    return block_rules, allow_rules

def write_output(output_file: Path, rules: Set[str], list_type: str):
    """写入输出文件"""
    header = f"""! Title: EasyAds {list_type}
! 更新时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
! 项目地址: https://github.com/EasyAds/EasyAds
!-------------------------------
"""
    with output_file.open('w', encoding='utf-8') as f:
        f.write(header)
        if rules:
            f.writelines(f"{rule}\n" for rule in sorted(rules))
        else:
            f.write(f"! 注意: 未找到有效的{list_type}规则\n")

def main():
    print("=== AdBlock规则合并处理 ===")
    
    # 路径设置
    tmp_dir = Path('tmp')
    rules_dir = Path('data/rules')
    rules_dir.mkdir(parents=True, exist_ok=True)

    # 合并源文件
    merged_file = tmp_dir / 'merged_rules.tmp'
    print_progress("正在合并源文件...")
    
    with merged_file.open('w', encoding='utf-8') as out:
        for src in sorted(tmp_dir.glob('*.txt')):
            print_progress(f"合并: {src.name}")
            try:
                content = src.read_text(encoding='utf-8')
                out.write(content + '\n')
            except:
                print_progress(f"跳过无法读取的文件: {src.name}")

    # 处理规则
    print_progress("\n开始规则处理...")
    block, allow = process_rules(merged_file)

    # 写入结果
    print_progress("\n写入结果文件...")
    write_output(rules_dir / 'adblock.txt', block, "拦截规则")
    write_output(rules_dir / 'allow.txt', allow, "放行规则")

    print("\n=== 处理完成 ===")
    print(f"最终结果: {len(block)} 条拦截规则, {len(allow)} 条放行规则")

if __name__ == '__main__':
    main()