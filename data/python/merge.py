import re
from pathlib import Path
import mmap
import logging
from typing import Set, Dict, List, Tuple, Optional, Callable, Pattern

class FullCompatProcessor:
    __slots__ = ['black_rules', 'white_rules', '_patterns']
    
    # 预定义正则模式
    BLACK_PATTERNS = [
        (r'^\|\|[^\s\\\/]+\^?.*$', None),
        (r'^127\.0\.0\.1\s+([\w.-]+)', lambda m: f"||{m.group(1)}^"),
        (r'^##[^#\s]', None),
        (r'^\|\|.+\$[a-z-]+(?!,)', None),
        (r'^.*\$important(?:,|$)', None),
        (r'^.*\$redirect=\w+', None)
    ]
    
    WHITE_PATTERNS = [
        (r'^@@\|\|[^\s\\\/]+\^?.*$', None),
        (r'^0\.0\.0\.0\s+([\w.-]+)', lambda m: f"@@||{m.group(1)}^"),
        (r'^#%#', None),
        (r'^@@.+\$[a-z-]+(?!,)', None)
    ]

    def __init__(self):
        self.black_rules: Set[str] = set()
        self.white_rules: Set[str] = set()
        self._patterns: Dict[str, List[Tuple[Pattern, Optional[Callable]]]] = {}  # 修复这里
        self._compile_patterns()
        
    def _compile_patterns(self) -> None:
        """编译正则表达式"""
        self._patterns = {
            'black': [(re.compile(pattern), processor) for pattern, processor in self.BLACK_PATTERNS],
            'white': [(re.compile(pattern), processor) for pattern, processor in self.WHITE_PATTERNS]
        }

    def _process_line(self, line: str) -> None:
        """处理单行规则"""
        line = line.strip()
        if not line or line.startswith('!'):
            return

        if line.startswith('$$') or (line.startswith('/') and line.endswith('/')):
            self.black_rules.add(line)
            return

        for pattern, processor in self._patterns['black']:
            if match := pattern.match(line):
                rule = processor(match) if processor else line
                self.black_rules.add(rule)
                return

        for pattern, processor in self._patterns['white']:
            if match := pattern.match(line):
                rule = processor(match) if processor else line
                self.white_rules.add(rule)
                return

        self.black_rules.add(line)

    def _check_conflicts(self) -> None:
        """检测规则冲突"""
        conflicts = self.black_rules & self.white_rules
        if conflicts:
            logging.info(
                f"发现 {len(conflicts)} 条冲突规则\n"
                f"示例: {sorted(conflicts)[:3]}"
            )

    def process_files(self, input_dir: str = 'tmp', output_dir: str = 'data/rules') -> None:
        """主处理流程"""
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            input_path = Path(input_dir)
            
            if not input_path.exists():
                raise FileNotFoundError(f"目录不存在: {input_dir}")

            for pattern in ['adblock*.txt', 'allow*.txt']:
                for file in input_path.glob(pattern):
                    try:
                        with file.open('r+') as f:
                            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                                for line in iter(mm.readline, b''):
                                    self._process_line(line.decode('utf-8', errors='ignore'))
                    except Exception as e:
                        logging.warning(f"处理文件失败 {file}: {e}")

            self._check_conflicts()

            with open(Path(output_dir)/'allow.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(self.white_rules)))
            
            with open(Path(output_dir)/'adblock.txt', 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted(self.black_rules)))

            logging.info(
                f"生成规则: 白名单({len(self.white_rules)}条), "
                f"黑名单({len(self.black_rules)}条)"
            )
        except Exception as e:
            logging.error(f"处理失败: {e}")
            raise

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    FullCompatProcessor().process_files()