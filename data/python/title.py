import datetime
import pytz
from pathlib import Path
from typing import Set

HEADER_TEMPLATE = """[Adblock Plus 2.0]
! Title: EasyAds
! Homepage: https://github.com/045200/EasyAds
! Expires: 12 Hours
! Version: {timestamp}（北京时间）
! Description: 适用于AdGuard的去广告规则，合并优质上游规则并去重整理排列
! Total count: {line_count}
"""

def get_beijing_time() -> str:
    """获取当前北京时间（精简版）"""
    return datetime.datetime.now(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')

def process_rule_files(target_files: Set[str], rules_dir: Path) -> None:
    """
    高效处理规则文件，添加标准头信息
    
    Args:
        target_files: 需要处理的目标文件名集合
        rules_dir: 规则文件目录路径
    """
    timestamp = get_beijing_time()
    
    for filename in target_files:
        file_path = rules_dir / filename
        if not file_path.exists():
            print(f"跳过不存在的文件: {filename}")
            continue

        try:
            # 单次读取完成统计和内容获取
            with file_path.open('r+', encoding='utf-8') as f:
                content = f.read()
                f.seek(0)
                
                # 统计有效规则行数
                line_count = sum(1 for line in content.splitlines() 
                              if line.strip() and not line.startswith('!'))
                
                # 写入新内容
                f.write(HEADER_TEMPLATE.format(
                    timestamp=timestamp,
                    line_count=line_count
                ) + content)
                f.truncate()

            print(f"已更新 {filename} (规则数: {line_count})")

        except Exception as e:
            print(f"处理 {filename} 失败: {e}")

if __name__ == "__main__":
    # 目标文件集合
    TARGET_FILES = {'adblock.txt', 'allow.txt', 'dns.txt', 'hosts.txt'}
    
    # 精简路径逻辑（假设脚本在 /data/python/ 目录下）
    RULES_DIR = Path(__file__).parent.parent  # 直接指向项目根目录
    
    # 验证路径
    if not RULES_DIR.exists():
        raise FileNotFoundError(f"规则目录不存在: {RULES_DIR}")
    
    process_rule_files(TARGET_FILES, RULES_DIR)