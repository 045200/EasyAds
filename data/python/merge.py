import re
from pathlib import Path
from collections import defaultdict
import mmap

class FullCompatProcessor:
    __slots__ = ['black_rules', 'white_rules', '_patterns']
    
    def __init__(self):
        # 预编译所有支持的正则表达式
        self._patterns = {
            'black': [
                re.compile(r'^\|\|[^\s^\\^\/]+\^?.*$'),  # 基础域名规则
                re.compile(r'^127\.0\.0\.1\s+([\w.-]+)'),  # Hosts黑名单
                re.compile(r'^##[^#\s]'),  # 元素隐藏
                re.compile(r'^\|\|.+\$[a-z-]+(?!,)')  # 基础修饰符
            ],
            'white': [
                re.compile(r'^@@\|\|[^\s^\\^\/]+\^?.*$'),  # 基础白名单
                re.compile(r'^0\.0\.0\.0\s+([\w.-]+)'),  # Hosts白名单
                re.compile(r'^#%#'),  # 脚本片段
                re.compile(r'^@@.+\$[a-z-]+(?!,)')  # 白名单修饰符
            ]
        }
        self.black_rules = set()
        self.white_rules = set()

    def _process_line(self, line: str) -> None:
        """支持全语法分类"""
        line = line.strip()
        if not line or line.startswith('!'):
            return

        # 黑名单检测
        for pattern in self._patterns['black']:
            if match := pattern.match(line):
                if pattern.pattern.startswith('127'):
                    self.black_rules.add(f"||{match.group(1)}^")
                else:
                    self.black_rules.add(line)
                return

        # 白名单检测
        for pattern in self._patterns['white']:
            if match := pattern.match(line):
                if pattern.pattern.startswith('0.0.0'):
                    self.white_rules.add(f"@@||{match.group(1)}^")
                else:
                    self.white_rules.add(line)
                return

        # 特殊语法检测（可选扩展）
        if line.startswith('$$'):
            self.black_rules.add(line)  # HTML过滤视为黑名单
        elif line.startswith('/') and line.endswith('/'):
            self.black_rules.add(line)  # 正则规则视为黑名单

    def process_files(self, input_dir: str = 'tmp', output_dir: str = 'data/rules'):
        """处理流程"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # 合并处理所有目标文件
        for pattern in ['adblock*.txt', 'allow*.txt']:
            for file in Path(input_dir).glob(pattern):
                with open(file, 'r+') as f:
                    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    for line in iter(mm.readline, b''):
                        self._process_line(line.decode('utf-8', errors='ignore'))
                    mm.close()

        # 写入结果
        with open(Path(output_dir)/'adblock.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.black_rules)))

        with open(Path(output_dir)/'allow.txt', 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(self.white_rules)))

        print(f"生成规则：\n┣ 黑名单({len(self.black_rules)}条)\n┗ 白名单({len(self.white_rules)}条)")

if __name__ == '__main__':
    FullCompatProcessor().process_files()