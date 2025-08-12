#!/usr/bin/env python3
"""
修复版AdBlock规则合并处理器
主要修复：
1. 正则表达式语法错误
2. 增强规则验证鲁棒性
"""

import re
import sys
from pathlib import Path
from typing import Set, Dict, Tuple
from datetime import datetime, timezone

class RuleProcessor:
    def __init__(self):
        self.counter = {
            'total': 0,
            'block': 0,
            'allow': 0,
            'rejected': 0,
            'duplicates': 0
        }
        self.rule_hashes = set()

    def _print_progress(self, message: str):
        print(f"\033[33m[STATUS] {message}\033[0m", file=sys.stderr)

    def _print_rejection(self, reason: str, rule: str):
        print(f"\033[31m[REJECTED] {reason}: {rule[:80]}{'...' if len(rule)>80 else ''}\033[0m", 
              file=sys.stderr)

    def _rule_hash(self, rule: str) -> str:
        return rule.strip().lower()

    def _is_duplicate(self, rule: str) -> bool:
        return self._rule_hash(rule) in self.rule_hashes

    def _validate_rule(self, rule: str) -> Tuple[bool, str]:
        """修复后的规则验证方法"""
        rule = rule.strip()
        if not rule:
            return False, "空规则"
        
        if rule.startswith('!') or '[Adblock' in rule:
            return False, "注释/声明"
        if '##' in rule or '#@#' in rule:
            return False, "元素隐藏规则"
        
        # 修复后的正则表达式
        if any(rule.startswith(x) for x in ('#?#', '$$', '@@||')):
            return True, ""
        
        # 更安全的正则模式
        if re.match(r'^[@]{0,2}[|*^~]?[a-zA-Z0-9_./%\-]+', rule):
            return True, ""
        
        return False, "无效格式"

    def process_file(self, file_path: Path) -> Tuple[Set[str], Set[str]]:
        """处理单个规则文件"""
        block_rules = set()
        allow_rules = set()

        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding='gbk')
            except:
                self._print_progress(f"无法解码文件: {file_path.name}")
                return block_rules, allow_rules

        self._print_progress(f"正在处理: {file_path.name} ({len(content.splitlines())}行)")

        for raw_line in content.splitlines():
            self.counter['total'] += 1
            line = raw_line.strip()

            if not line or line.startswith(('!', '#')) or '[Adblock' in line:
                continue

            # 转换hosts格式规则
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+', line):
                domain = line.split()[1]
                if re.match(r'^[a-zA-Z0-9._-]+$', domain):
                    line = f"||{domain}^"

            try:
                valid, reason = self._validate_rule(line)
                if not valid:
                    self.counter['rejected'] += 1
                    self._print_rejection(reason, raw_line)
                    continue

                if self._is_duplicate(line):
                    self.counter['duplicates'] += 1
                    continue

                if line.startswith('@@'):
                    allow_rules.add(line)
                    self.counter['allow'] += 1
                else:
                    block_rules.add(line)
                    self.counter['block'] += 1

                self.rule_hashes.add(self._rule_hash(line))
            except Exception as e:
                self._print_rejection(f"验证错误: {str(e)}", raw_line)

        return block_rules, allow_rules

def generate_header(list_type: str) -> str:
    return f"""! Title: EasyAds {list_type}
! Version: {datetime.now(timezone.utc).strftime('%Y%m%d')}
! Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
! Expires: 1 days
! Homepage: https://github.com/EasyAds/EasyAds
!-------------------------------
"""

def main():
    print("=== AdBlock规则合并处理器(修复版) ===")
    processor = RuleProcessor()
    tmp_dir = Path('tmp')
    output_dir = Path('data/rules')
    output_dir.mkdir(parents=True, exist_ok=True)

    all_block = set()
    all_allow = set()

    # 先处理放行规则
    for file in sorted(tmp_dir.glob('allow*.txt')):
        block, allow = processor.process_file(file)
        all_allow.update(allow)
    
    # 再处理拦截规则
    for file in sorted(tmp_dir.glob('adblock*.txt')):
        block, allow = processor.process_file(file)
        all_block.update(block)

    # 最终过滤
    final_block = all_block - {x[2:] for x in all_allow if x.startswith('@@')}
    
    # 写入结果
    with open(output_dir/'adblock.txt', 'w', encoding='utf-8') as f:
        f.write(generate_header("拦截规则"))
        f.writelines(f"{rule}\n" for rule in sorted(final_block))

    with open(output_dir/'allow.txt', 'w', encoding='utf-8') as f:
        f.write(generate_header("放行规则"))
        f.writelines(f"{rule}\n" for rule in sorted(all_allow))

    print("\n=== 处理结果统计 ===")
    print(f"总处理规则: {processor.counter['total']}")
    print(f"有效拦截规则: {len(final_block)}")
    print(f"有效放行规则: {len(all_allow)}")
    print(f"重复规则: {processor.counter['duplicates']}")
    print(f"被拒绝规则: {processor.counter['rejected']}")

if __name__ == '__main__':
    main()