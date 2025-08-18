import subprocess
import datetime
import pytz
from pathlib import Path
import re

def update_readme():
    """更新README.md中的规则计数和时间戳"""
    try:
        # 获取脚本所在目录的父目录（项目根目录）
        base_dir = Path(__file__).parent.parent.parent
        
        # 定义文件路径（相对于项目根目录）
        rule_files = {
            'adblock': base_dir / 'adblock.txt',
            'dns': base_dir / 'dns.txt',
            'allow': base_dir / 'allow.txt',
            'hosts': base_dir / 'hosts.txt'
        }

        # 验证文件存在
        for name, path in rule_files.items():
            if not path.exists():
                raise FileNotFoundError(f"规则文件不存在: {path}")

        # 提取规则计数
        counts = {}
        for name, path in rule_files.items():
            try:
                # 使用Python原生方式获取行数（比sed更可靠）
                with open(path, 'r', encoding='utf-8') as f:
                    # 计算非空非注释行
                    lines = [line for line in f if line.strip() and not line.startswith(('#', '!'))]
                    counts[name] = str(len(lines))
            except Exception as e:
                raise ValueError(f"无法统计 {path}: {str(e)}")

        # 获取北京时间
        beijing_time = (datetime.datetime.now(pytz.timezone('UTC'))
                      .astimezone(pytz.timezone('Asia/Shanghai'))
                      .strftime('%Y-%m-%d %H:%M:%S'))

        # 更新README.md（位于项目根目录）
        readme_path = base_dir / 'README.md'
        if not readme_path.exists():
            raise FileNotFoundError("README.md不存在于项目根目录")

        # 读取并更新内容
        with open(readme_path, 'r+', encoding='utf-8') as f:
            content = f.read()
            
            replacements = {
                r'更新时间:.*': f'更新时间: {beijing_time} （北京时间）',
                r'拦截规则数量.*': f'拦截规则数量: {counts["adblock"]}',
                r'DNS拦截规则数量.*': f'DNS拦截规则数量: {counts["dns"]}',
                r'白名单规则数量.*': f'白名单规则数量: {counts["allow"]}',
                r'hosts规则数量.*': f'Hosts规则数量: {counts["hosts"]}'
            }

            for pattern, repl in replacements.items():
                content = re.sub(pattern, repl, content)
            
            # 写回文件
            f.seek(0)
            f.write(content)
            f.truncate()

        print(f"成功更新 {readme_path}")
        return True

    except Exception as e:
        print(f"更新失败: {str(e)}")
        return False

if __name__ == "__main__":
    update_readme()