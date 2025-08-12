import re
from pathlib import Path
from collections import defaultdict
import mmap
import logging
from typing import Set, Dict, List, Tuple, Optional

class FullCompatProcessor:
    __slots__ = ['black_rules', 'white_rules', '_patterns']
    
    # 预定义正则模式（含现代语法支持）
    BLACK_PATTERNS = [
        (r'^\|\|[^\s\\\/]+\^?.*$', None),                 # 基础域名规则
        (r'^127\.0\.0\.1\s+([\w.-]+)', lambda m: f"||{m.group(1)}^"),  # Hosts转ABP
        (r'^##[^#\s]', None),                             # 元素隐藏
        (r'^\|\|.+\$[a-z-]+(?!,)', None),                 # 基础修饰符
        (r'^.*\$important(?:,|$)', None),                 # $important修饰符
        (r'^.*\$redirect=\w+', None)                      # $redirect修饰符
    ]
    
    WHITE_PATTERNS = [
        (r'^@@\|\|[^\s\\\/]+\^?.*$', None),               # 基础白名单
        (r'^0\.0\.0\.0\s+([\w.-]+)', lambda m: f"@@||{m.group(1)}^"),  # Hosts转ABP
        (r'^#%#', None),                                  # 脚本片段
        (r'^@@.+\$[a-z-]+(?!,)', None)                    # 白名单修饰符
    ]

    def __init__(self):
        self.black_rules: Set[str] = set()
        self.white_rules: Set[str] = set()
        self._compile_patterns()
        
    def _compile_patterns(self) -> None:
        """预编译所有正则表达式"""
        self._patterns: Dict[str, List[Tuple[re.Pattern, Optional[callable]]] = {
            'black': [(re.compile(pattern), processor) for pattern, processor in self.BLACK_PATTERNS],
            'white': [(re.compile(pattern), processor) for pattern, processor in self.WHITE_PATTERNS]
        }

    def _process_line(self, line: str) -> None:
        """处理单行规则并分类"""
        line = line.strip()
        if not line or line.startswith('!'):
            return

        # 特殊语法（HTML过滤、正则规则视为黑名单）
        if line.startswith('$$') or (line.startswith('/') and line.endswith('/')):
            self.black_rules.add(line)
            return

        # 检查黑名单模式
        for pattern, processor in self._patterns['black']:
            if match := pattern.match(line):
                rule = processor(match) if processor else line
                self.black_rules.add(rule)
                return

        # 检查白名单模式
        for pattern, processor in self._patterns['white']:
            if match := pattern.match(line):
                rule = processor(match) if processor else line
                self.white_rules.add(rule)
                return

        # 未分类的规则默认视为黑名单
        self.black_rules.add(line)

    def _check_conflicts(self) -> None:
        """检测黑白名单冲突并记录日志（现在只是信息性提示）"""
        conflicts = self.black_rules & self.white_rules
        if conflicts:
            logging.info(
                f"发现 {len(conflicts)} 条规则同时存在于黑白名单中（正常现象，白名单会覆盖对应黑名单）。"
                f"示例: {list(conflicts)[:5]}"
            )

    def _remove_duplicates(self) -> None:
        """分别对黑白名单进行去重（保留最后出现的规则）"""
        # 使用有序字典保持最后出现的规则
        def deduplicate(rules: Set[str]) -> List[str]:
            return list(dict.fromkeys(reversed(sorted(rules)))[::-1])
        
        self.black_rules = deduplicate(self.black_rules)
        self.white_rules = deduplicate(self.white_rules)

    def process_files(self, input_dir: str = 'tmp', output_dir: str = 'data/rules') -> None:
        """处理流程：合并 → 分类 → 去重 → 冲突检测 → 输出"""
        try:
            # 1. 准备目录
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            input_path = Path(input_dir)
            if not input_path.exists():
                raise FileNotFoundError(f"输入目录不存在: {input_dir}")

            # 2. 合并并分类所有规则文件
            for pattern in ['adblock*.txt', 'allow*.txt']:
                for file in input_path.glob(pattern):
                    try:
                        with file.open('r+') as f:
                            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                for line in iter(mm.readline, b''):
                                    self._process_line(line.decode('utf-8', errors='ignore'))
                    except Exception as e:
                        logging.warning(f"文件处理失败 {file}: {str(e)}")

            # 3. 去重和冲突检测
            self._remove_duplicates()
            self._check_conflicts()

            # 4. 输出结果（保持所有规则）
            with open(Path(output_dir)/'allow.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.white_rules))
            
            with open(Path(output_dir)/'adblock.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.black_rules))

            logging.info(
                f"规则生成完成: 白名单({len(self.white_rules)}条), 黑名单({len(self.black_rules)}条)"
            )
        except Exception as e:
            logging.error(f"处理失败: {str(e)}")
            raise

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    FullCompatProcessor().process_files()