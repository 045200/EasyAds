#!/usr/bin/env python3
"""
AdBlock规则合并去重处理器
功能：合并多个规则文件，去除重复项，生成最终版的黑白名单
输出：adblock.txt(拦截规则)和allow.txt(放行规则)
"""

import re
import sys
from pathlib import Path
from typing import Set, Dict, Tuple
from datetime import datetime, timezone

class RuleProcessor:
    def __init__(self):
        # 规则统计计数器
        self.counter = {
            'total': 0,
            'block': 0,
            'allow': 0,
            'rejected': 0,
            'duplicates': 0
        }
        # 内存优化：存储规则哈希值用于去重
        self.rule_hashes = set()

    def _print_progress(self, message: str):
        """实时进度显示（黄色文本）"""
        print(f"\033[33m[STATUS] {message}\033[0m", file=sys.stderr)

    def _print_rejection(self, reason: str, rule: str):
        """规则拒绝通知（红色文本）"""
        print(f"\033[31m[REJECTED] {reason}: {rule[:80]}{'...' if len(rule)>80 else ''}\033[0m", 
              file=sys.stderr)

    def _rule_hash(self, rule: str) -> str:
        """生成规则唯一标识（优化去重性能）"""
        return rule.strip().lower()

    def _is_duplicate(self, rule: str) -> bool:
        """检查是否重复规则"""
        return self._rule_hash(rule) in self.rule_hashes

    def _validate_rule(self, rule: str) -> Tuple[bool, str]:
        """增强型规则验证"""
        rule = rule.strip()
        if not rule:
            return False, "空规则"
        
        # 注释和元素隐藏规则
        if rule.startswith('!') or '[Adblock' in rule:
            return False, "注释/声明"
        if '##' in rule or '#@#' in rule:
            return False, "元素隐藏规则"
        
        # 特殊规则类型
        if any(rule.startswith(x) for x in ('#?#', '$$', '@@||')):
            return True, ""
        
        # 标准规则格式
        if re.match(r'^([@]{0,2}[|*^~]?[a-zA-Z0-9_./%-]+', rule):
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

            # 跳过空行和注释
            if not line or line.startswith(('!', '#')) or '[Adblock' in line:
                continue

            # 转换hosts格式规则
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+', line):
                domain = line.split()[1]
                if re.match(r'^[a-zA-Z0-9._-]+$', domain):
                    line = f"||{domain}^"

            # 验证规则有效性
            valid, reason = self._validate_rule(line)
            if not valid:
                self.counter['rejected'] += 1
                self._print_rejection(reason, raw_line)
                continue

            # 去重检查
            if self._is_duplicate(line):
                self.counter['duplicates'] += 1
                continue

            # 规则分类
            if line.startswith('@@'):
                allow_rules.add(line)
                self.counter['allow'] += 1
            else:
                block_rules.add(line)
                self.counter['block'] += 1

            self.rule_hashes.add(self._rule_hash(line))

        return block_rules, allow_rules

def generate_header(list_type: str) -> str:
    """生成规则文件头部信息"""
    return f"""! Title: EasyAds {list_type}
! Version: {datetime.now(timezone.utc).strftime('%Y%m%d')}
! Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
! Expires: 1 days
! Homepage: https://github.com/EasyAds/EasyAds
!-------------------------------
"""

def main():
    print("=== AdBlock规则合并处理器 ===")
    processor = RuleProcessor()
    tmp_dir = Path('tmp')
    output_dir = Path('data/rules')
    output_dir.mkdir(parents=True, exist_ok=True)

    # 合并所有规则文件
    all_block = set()
    all_allow = set()

    # 处理顺序：先处理放行规则再处理拦截规则
    for file in sorted(tmp_dir.glob('allow*.txt')) + sorted(tmp_dir.glob('adblock*.txt')):
        block, allow = processor.process_file(file)
        all_block.update(block)
        all_allow.update(allow)

    # 最终过滤：确保放行规则优先于拦截规则
    final_block = all_block - {x[2:] for x in all_allow if x.startswith('@@')}
    
    # 写入结果文件
    with open(output_dir/'adblock.txt', 'w', encoding='utf-8') as f:
        f.write(generate_header("拦截规则"))
        f.writelines(f"{rule}\n" for rule in sorted(final_block))

    with open(output_dir/'allow.txt', 'w', encoding='utf-8') as f:
        f.write(generate_header("放行规则"))
        f.writelines(f"{rule}\n" for rule in sorted(all_allow))

    # 输出统计报告
    print("\n=== 处理结果统计 ===")
    print(f"总处理规则: {processor.counter['total']}")
    print(f"有效拦截规则: {len(final_block)} (去重后)")
    print(f"有效放行规则: {len(all_allow)} (去重后)")
    print(f"重复规则: {processor.counter['duplicates']}")
    print(f"被拒绝规则: {processor.counter['rejected']}")
    print(f"\n输出文件: {output_dir}/adblock.txt, {output_dir}/allow.txt")

if __name__ == '__main__':
    main()