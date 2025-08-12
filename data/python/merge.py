import os
import re
from pathlib import Path

def process_rules(input_dir='tmp', output_dir='data/rules'):
    # 初始化集合
    adblock_black = set()  # 标准AdBlock拦截规则（||domain^）
    adblock_white = set()  # 标准AdBlock白名单（@@||domain^）
    hosts_black = set()    # Hosts转换的拦截规则
    hosts_white = set()    # Hosts转换的放行规则
    other_rules = set()    # 新增：其他不处理的规则原样保留

    # 处理所有输入文件
    for filename in os.listdir(input_dir):
        filepath = os.path.join(input_dir, filename)
        if not os.path.isfile(filepath):
            continue

        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('! ', '# ', '!#')):  # 严格匹配注释符号
                    continue

                # 1. 处理AdBlock语法规则
                if line.startswith('@@'):
                    if any(c in line for c in ['^', '$']):
                        adblock_white.add(line)
                    else:
                        other_rules.add(line)  # 非常规白名单规则保留
                elif any(c in line for c in ['^', '$']):
                    adblock_black.add(line)

                # 2. 处理hosts语法规则
                elif re.match(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$', line):
                    ip, domain = line.split()
                    if ip == '127.0.0.1':
                        hosts_black.add(f'||{domain}^')
                    elif ip == '0.0.0.0':
                        hosts_white.add(f'@@||{domain}^')

                # 3. 其他规则原样保留
                else:
                    other_rules.add(line)

    # 合并规则（保持分类清晰）
    final_black = sorted(adblock_black.union(hosts_black))
    final_white = sorted(adblock_white.union(hosts_white))
    final_other = sorted(other_rules)

    # 确保输出目录存在
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # 写入文件（黑名单+其他规则 / 白名单+其他规则）
    with open(os.path.join(output_dir, 'adblock.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_black))
        if final_other:
            f.write('\n\n! 其他未分类规则（原样保留）\n')
            f.write('\n'.join(r for r in final_other if not r.startswith('@@')))

    with open(os.path.join(output_dir, 'allow.txt'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_white))
        if final_other:
            f.write('\n\n! 其他未分类规则（原样保留）\n')
            f.write('\n'.join(r for r in final_other if r.startswith('@@')))

    print(f"规则处理完成：黑名单 {len(final_black)} 条，白名单 {len(final_white)} 条，其他规则 {len(final_other)} 条")

if __name__ == '__main__':
    process_rules()