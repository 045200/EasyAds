#!/usr/bin/env python3
"""
AdGuard Home 规则优化处理器
修复问题：
1. 白名单规则误判
2. 拦截规则误判
3. 增强 hosts 规则支持
"""

import re
import sys
from pathlib import Path
from typing import Set, Tuple
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
        print(f"[STATUS] {message}", file=sys.stderr)

    def _print_rejection(self, reason: str, rule: str):
        print(f"[REJECTED] {reason}: {rule[:100]}{'...' if len(rule)>100 else ''}", file=sys.stderr)

    def _rule_hash(self, rule: str) -> str:
        return rule.strip().lower()

    def _is_duplicate(self, rule: str) -> bool:
        return self._rule_hash(rule) in self.rule_hashes

    def _validate_rule(self, rule: str) -> Tuple[bool, str]:
        """AdGuard Home 兼容的规则验证"""
        rule = rule.strip()
        if not rule:
            return False, "空规则"

        # 注释和声明
        if rule.startswith('!') or rule.startswith('[Adblock'):
            return False, "注释"

        # 元素隐藏规则
        if '##' in rule or '#@#' in rule:
            return False, "元素隐藏"

        # 放行规则（增强白名单检测）
        if rule.startswith('@@'):
            return True, ""

        # 常见规则前缀
        valid_prefixes = (
            '||', '|', 'http://', 'https://', 
            '/', '*', '^', '$', '~',
            'domain=', 'ip6-cidr:', 'ip-cidr:'
        )
        if any(rule.startswith(p) for p in valid_prefixes):
            return True, ""

        # 标准域名模式
        if re.match(r'^([a-zA-Z0-9*_-]+\.)+[a-zA-Z]{2,}(/|$|\^|\|)', rule):
            return True, ""

        # Hosts 格式兼容
        if re.match(r'^[a-zA-Z0-9.*_-]+$', rule):
            return True, ""

        return False, "无效格式"

    def process_file(self, file_path: Path) -> Tuple[Set[str], Set[str]]:
        """处理文件并返回 (block_rules, allow_rules)"""
        block_rules = set()
        allow_rules = set()

        try:
            content = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding='gbk')
            except:
                self._print_progress(f"解码失败: {file_path.name}")
                return block_rules, allow_rules

        self._print_progress(f"处理: {file_path.name} ({len(content.splitlines())}行)")

        for raw_line in content.splitlines():
            self.counter['total'] += 1
            line = raw_line.strip()

            # 跳过注释和空行
            if not line or line.startswith(('!', '#')) or '[Adblock' in line:
                continue

            # 转换 hosts 格式
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+', line):
                parts = line.split()
                if len(parts) > 1 and re.match(r'^[a-zA-Z0-9.*-]+$', parts[1]):
                    line = f"||{parts[1]}^"

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
                self._print_rejection(f"处理错误: {str(e)}", raw_line)

        return block_rules, allow_rules

def generate_header(list_type: str) -> str:
    return f"""! Title: AdGuard Home {list_type}
! Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
! Expires: 1 day
! Homepage: https://github.com/EasyAds/EasyAds
!-------------------------------
"""

def main():
    print("=== AdGuard Home 规则处理器 ===")
    processor = RuleProcessor()
    input_dir = Path('tmp')
    output_dir = Path('data/rules')
    output_dir.mkdir(parents=True, exist_ok=True)

    # 先处理放行规则
    all_allow = set()
    for file in sorted(input_dir.glob('allow*.txt')):
        _, allow = processor.process_file(file)
        all_allow.update(allow)

    # 再处理拦截规则
    all_block = set()
    for file in sorted(input_dir.glob('adblock*.txt')):
        block, _ = processor.process_file(file)
        all_block.update(block)

    # 冲突处理：确保放行规则优先
    final_block = all_block - {x[2:] for x in all_allow if x.startswith('@@')}

    # 写入结果
    with open(output_dir/'adblock.txt', 'w', encoding='utf-8') as f:
        f.write(generate_header("拦截规则"))
        f.writelines(f"{rule}\n" for rule in sorted(final_block))

    with open(output_dir/'allow.txt', 'w', encoding='utf-8') as f:
        f.write(generate_header("放行规则"))
        f.writelines(f"{rule}\n" for rule in sorted(all_allow))

    # 输出统计
    print("\n=== 处理结果 ===")
    print(f"总规则: {processor.counter['total']}")
    print(f"有效拦截: {len(final_block)}")
    print(f"有效放行: {len(all_allow)}")
    print(f"重复丢弃: {processor.counter['duplicates']}")
    print(f"无效规则: {processor.counter['rejected']}")

if __name__ == '__main__':
    main()