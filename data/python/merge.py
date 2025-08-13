import re
from pathlib import Path
import mmap
import logging
from typing import Set, Dict, List, Tuple, Optional, Callable, Pattern
import hashlib

class UltimateRuleProcessor:
    __slots__ = ['black_rules', 'white_rules', '_patterns', 'config']
    
    # 配置模板
    DEFAULT_CONFIG = {
        'keep_hosts_syntax': False,
        'remove_duplicates': True,
        'minify_output': False,
        'validate_rules': True,
        'backup_original': True,
        'conflict_resolution': 'whitelist_priority'  # or 'blacklist_priority'
    }

    # 完整语法支持（覆盖所有主流拦截器）
    FULL_SYNTAX = {
        'black': [
            # Hosts格式
            (r'^(?:127\.0\.0\.1|0\.0\.0\.0|::)\s+([\w.-]+)', 
             lambda m, cfg: m.group(0) if cfg['keep_hosts_syntax'] else f"||{m.group(1)}^"),
            
            # 标准AdBlock
            (r'^\|\|([^\s\\\/]+)\^?$', None),
            (r'^\|\|([^\s\\\/]+)\^?\$[a-z-_,=]+', None),  # 全参数支持
            (r'^/.*/$', None),  # 正则
            
            # AdGuard扩展
            (r'^\|\|.*\$\$.*', None),  # 元素隐藏
            (r'^\$.*$', None),         # 脚本规则
            (r'^\|\|.*\^dns$', None),  # DNS过滤
            
            # uBlock扩展
            (r'^\.\w+$', None),       # 域名前缀
            (r'^\*://\*\.\w+/*$', None),  # 通配符
            (r'^[a-z-]+:\/\/.*$', None),  # 协议规则
            
            # 特殊规则
            (r'^!.*$', None),          # 注释保留
            (r'^\[Adblock.*\]$', None) # 文件头
        ],
        'white': [
            # 标准白名单
            (r'^@@\|\|([^\s\\\/]+)\^?$', None),
            (r'^@@\d+\.\d+\.\d+\.\d+\s+([\w.-]+)', 
             lambda m, cfg: m.group(0) if cfg['keep_hosts_syntax'] else f"@@||{m.group(1)}^"),
            
            # 扩展白名单
            (r'^@@/.*/$', None),
            (r'^@@##\w+', None),
            (r'^@@\$\w+', None),
            (r'^@@\.\w+$', None),
            (r'^@@\*://\*\.\w+/*$', None),
            (r'^@@[a-z-]+:\/\/.*$', None),
            
            # 特殊白名单
            (r'^@@\|\|.*\^dns$', None)  # DNS例外
        ]
    }

    def __init__(self, **kwargs):
        """
        :param kwargs: 可覆盖DEFAULT_CONFIG的配置项
        """
        self.black_rules = set()
        self.white_rules = set()
        self.config = self.DEFAULT_CONFIG | kwargs
        self._compile_patterns()
        
        # 初始化日志
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler('rule_processor.log'),
                logging.StreamHandler()
            ]
        )

    def _compile_patterns(self) -> None:
        """动态编译正则模式（支持配置感知）"""
        self._patterns = {
            typ: [(re.compile(pattern), 
                  processor if not processor else lambda m, p=processor: p(m, self.config))
                for pattern, processor in self.FULL_SYNTAX[typ]]
            for typ in ['black', 'white']
        }

    def _process_line(self, line: str, is_whitelist: bool) -> bool:
        """
        处理单行规则
        :return: 是否成功处理
        """
        line = line.strip()
        if not line:
            return False

        # 注释和文件头特殊处理
        if line.startswith('!') or line.startswith('[Adblock'):
            if self.config['keep_comments']:
                (self.white_rules if is_whitelist else self.black_rules).add(line)
            return True

        patterns = self._patterns['white'] if is_whitelist else self._patterns['black']
        target_set = self.white_rules if is_whitelist else self.black_rules
        
        for pattern, processor in patterns:
            if match := pattern.match(line):
                processed = processor(match) if processor else line
                target_set.add(processed)
                return True
        
        # 未匹配时的处理
        if is_whitelist:
            if line.startswith('@@'):
                self.white_rules.add(line)
                return True
            logging.warning(f"无效白名单规则: {line[:50]}...")
        else:
            self.black_rules.add(line)
            return True

    def process_files(self, input_dir: str = 'input', output_dir: str = 'output') -> None:
        """增强的文件处理流程"""
        input_path = Path(input_dir)
        output_path = Path(output_dir)
        
        try:
            # 备份原始文件（可选）
            if self.config['backup_original']:
                self._backup_files(input_path)
            
            # 创建输出目录
            output_path.mkdir(parents=True, exist_ok=True)
            
            # 并行处理所有规则文件
            file_types = [
                ('adblock*.txt', False),
                ('allow*.txt', True),
                ('*.rules', None)  # 自动检测类型
            ]
            
            for pattern, is_whitelist in file_types:
                for file in input_path.glob(pattern):
                    self._process_single_file(file, is_whitelist)
            
            # 后处理
            self._post_process()
            
            # 保存结果
            self._save_rules(output_path)
            
        except Exception as e:
            logging.critical(f"处理失败: {e}", exc_info=True)
            raise

    def _process_single_file(self, file: Path, is_whitelist: Optional[bool]) -> None:
        """处理单个文件（带自动类型检测）"""
        try:
            # 自动检测文件类型
            if is_whitelist is None:
                with file.open('r', encoding='utf-8') as f:
                    first_line = f.readline()
                is_whitelist = first_line.startswith('@@')
            
            # 实际处理
            with file.open('rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for line in iter(mm.readline, b''):
                        try:
                            self._process_line(
                                line.decode('utf-8', errors='replace').strip(),
                                is_whitelist
                            )
                        except UnicodeError:
                            logging.warning(f"编码错误已跳过: {file.name}")
            
            logging.info(f"处理完成: {file.name} ({'白名单' if is_whitelist else '黑名单'})")
            
        except PermissionError:
            logging.error(f"权限拒绝: {file}")
        except Exception as e:
            logging.error(f"处理文件失败 {file}: {e}")

    def _post_process(self) -> None:
        """后处理（去重、验证、冲突解决）"""
        # 去重
        if self.config['remove_duplicates']:
            self._remove_duplicates()
        
        # 规则验证
        if self.config['validate_rules']:
            self._validate_rules()
        
        # 冲突解决
        self._resolve_conflicts()

    def _remove_duplicates(self) -> None:
        """高级去重（基于规则指纹）"""
        def get_fingerprint(rule):
            # 忽略大小写和多余空格
            clean = re.sub(r'\s+', '', rule.lower())
            return hashlib.md5(clean.encode()).hexdigest()
        
        # 黑白名单各自去重
        self.black_rules = {rule for rule in self.black_rules 
                          if not rule.startswith('!')}
        self.white_rules = {rule for rule in self.white_rules 
                          if not rule.startswith('!')}
        
        # 跨列表去重（根据配置）
        if self.config['conflict_resolution'] == 'whitelist_priority':
            black_fps = {get_fingerprint(rule) for rule in self.black_rules}
            self.white_rules = {
                rule for rule in self.white_rules
                if not (rule.startswith('@@') and 
                      get_fingerprint(rule[2:]) in black_fps)
            }
        else:  # blacklist_priority
            white_fps = {get_fingerprint(rule[2:]) 
                        for rule in self.white_rules 
                        if rule.startswith('@@')}
            self.black_rules = {
                rule for rule in self.black_rules
                if get_fingerprint(rule) not in white_fps
            }

    def _validate_rules(self) -> None:
        """规则语法验证"""
        invalid = set()
        
        # 验证黑名单
        for rule in self.black_rules:
            if not any(p.match(rule) for p, _ in self._patterns['black']):
                invalid.add(rule)
        
        # 验证白名单
        for rule in self.white_rules:
            if not any(p.match(rule) for p, _ in self._patterns['white']):
                invalid.add(rule)
        
        if invalid:
            logging.warning(f"发现 {len(invalid)} 条无效规则\n示例: {sorted(invalid)[:3]}")

    def _resolve_conflicts(self) -> None:
        """智能冲突解决"""
        # 提取基础域名（用于精准匹配）
        def extract_domain(rule):
            if match := re.match(r'^\|\|([^\s\\\/^]+)', rule):
                return match.group(1)
            return None
        
        black_domains = {extract_domain(r) for r in self.black_rules if extract_domain(r)}
        white_domains = {extract_domain(r[2:]) for r in self.white_rules 
                        if r.startswith('@@') and extract_domain(r[2:])}
        
        conflicts = black_domains & white_domains
        if conflicts:
            logging.warning(
                f"发现 {len(conflicts)} 条域名级冲突\n"
                f"解决方案: {self.config['conflict_resolution']}\n"
                f"示例冲突: {sorted(conflicts)[:5]}"
            )

    def _save_rules(self, output_dir: Path) -> None:
        """增强的规则保存"""
        # 准备内容
        black_content = sorted(self.black_rules, key=lambda x: x.lower())
        white_content = sorted(self.white_rules, key=lambda x: x.lower())
        
        # 最小化输出
        if self.config['minify_output']:
            black_content = [rule for rule in black_content if not rule.startswith('!')]
            white_content = [rule for rule in white_content if not rule.startswith('!')]
        
        # 写入文件
        try:
            with (output_dir / 'adblock.txt').open('w', encoding='utf-8') as f:
                f.write('\n'.join(black_content))
            
            with (output_dir / 'allow.txt').open('w', encoding='utf-8') as f:
                f.write('\n'.join(white_content))
            
            logging.info(
                f"规则已保存: 黑名单 {len(black_content)} 条, 白名单 {len(white_content)} 条\n"
                f"输出目录: {output_dir.resolve()}"
            )
        except IOError as e:
            logging.error(f"保存失败: {e}")
            raise

    def _backup_files(self, input_dir: Path) -> None:
        """创建输入文件备份"""
        backup_dir = input_dir / 'backup'
        backup_dir.mkdir(exist_ok=True)
        
        for file in input_dir.glob('*'):
            if file.is_file():
                backup = backup_dir / f"{file.name}.bak"
                backup.write_text(file.read_text())
        
        logging.info(f"已创建备份至: {backup_dir}")

if __name__ == '__main__':
    # 示例配置（可覆盖默认值）
    processor = UltimateRuleProcessor(
        keep_hosts_syntax=True,
        conflict_resolution='whitelist_priority',
        minify_output=True
    )
    processor.process_files()