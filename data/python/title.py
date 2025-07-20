import datetime
import pytz
from pathlib import Path
from typing import Set

HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: GOODBYEADS
! Homepage: https://github.com/045200/GOODBYEADS
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
"""

def get_beijing_time() -> str:
    """获取当前北京时间"""
    utc_time = datetime.datetime.now(pytz.timezone('UTC'))
    return utc_time.astimezone(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

def process_rule_files(target_files: Set[str], rules_dir: Path) -> None:
    """
    处理规则文件，添加标准头信息
    
    Args:
        target_files: 需要处理的目标文件名集合
        rules_dir: 规则文件目录路径
    """
    beijing_time = get_beijing_time()
    
    for file_path in rules_dir.glob('*.txt'):
        if file_path.name not in target_files:
            continue
            
        try:
            # 读取文件内容并计算行数
            with file_path.open('r', encoding='utf-8') as file:
                lines = file.readlines()
                line_count = len(lines)
                content = ''.join(lines)
            
            # 生成新内容
            new_content = HEADER_TEMPLATE.format(
                timestamp=beijing_time,
                line_count=line_count
            ) + content
            
            # 写回文件
            with file_path.open('w', encoding='utf-8') as file:
                file.write(new_content)
                
            print(f"Processed {file_path.name} with {line_count} rules")
                
        except IOError as e:
            print(f"Error processing {file_path.name}: {e}")

if __name__ == "__main__":
    target_files = {'adblock.txt', 'allow.txt', 'dns.txt'}
    rules_dir = Path(__file__).parent / 'data' / 'rules'
    
    if not rules_dir.exists():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")
    
    process_rule_files(target_files, rules_dir)