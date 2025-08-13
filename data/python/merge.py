#!/usr/bin/env python3
"""
规则合并去重脚本 - 适配下载脚本版
功能：
1. 自动识别tmp目录下的adblock*.txt和allow*.txt文件
2. 多语法规则支持（含Hosts/AdBlock/AdGuard等格式）
3. 智能冲突解决
4. 高性能处理（百万级规则秒级处理）
"""

import re
import os
import time
import mmap
import logging
import hashlib
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Set, Dict, List, Tuple, Optional

class RuleMerger:
    __slots__ = ['black_rules', 'white_rules', '_patterns', 'config']
    
    # 配置参数（适配下载脚本的输出结构）
    DEFAULT_CONFIG = {
        'input_dir': './tmp',          # 下载脚本的输出目录
        'output_dir': './data/rules',  # 最终规则存放目录
        'keep_hosts_syntax': False,    # 是否保留原始Hosts格式
        'remove_duplicates': True,     # 是否去重
        'minify_output': True,         # 是否移除注释
        'validate_rules': False,       # 是否验证规则（性能敏感时建议关闭）
        'conflict_resolution': 'whitelist_priority',  # 冲突解决策略
        'max_file_size_mb': 50         # 最大处理文件大小(MB)
    }

    # 预编译正则（优化性能）
    _HOSTS_PATTERN = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::)\s+([\w.-]+)')
    _DOMAIN_PATTERN = re.compile(r'^\|\|([^\s\\\/^]+)')
    _COMMENT_PATTERN = re.compile(r'^[![]')

    def __init__(self, **kwargs):
        """初始化处理器（适配下载脚本的输出结构）"""
        self.black_rules = set()
        self.white_rules = set()
        self.config = self.DEFAULT_CONFIG | kwargs
        self._compile_patterns()
        self._init_logging()

    def _init_logging(self):
        """配置日志输出（适配CI环境）"""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(levelname)s] %(message)s',
            handlers=[logging.StreamHandler()]
        )

    def _compile_patterns(self):
        """编译正则表达式（优化性能）"""
        self._patterns = {
            'black': [
                (self._HOSTS_PATTERN, lambda m: m.group(0) if self.config['keep_hosts_syntax'] else f"||{m.group(1)}^"),
                (re.compile(r'^\|\|([^\s\\\/]+)\^?$'), None),
                (re.compile(r'^\|\|([^\s\\\/]+)\^?\$[a-z-_,=]+'), None),
                (re.compile(r'^/.*/$'), None),
                (re.compile(r'^\$.*$'), None),
                (re.compile(r'^!.*$'), None)
            ],
            'white': [
                (re.compile(r'^@@\|\|([^\s\\\/]+)\^?$'), None),
                (re.compile(r'^@@\d+\.\d+\.\d+\.\d+\s+([\w.-]+'), 
                 lambda m: m.group(0) if self.config['keep_hosts_syntax'] else f"@@||{m.group(1)}^"),
                (re.compile(r'^@@/.*/$'), None),
                (re.compile(r'^@@##\w+'), None)
            ]
        }

    def process_files(self) -> bool:
        """主处理流程（适配下载脚本结构）"""
        try:
            input_path = Path(self.config['input_dir']).resolve()
            output_path = Path(self.config['output_dir']).resolve()
            
            # 自动创建目录（兼容下载脚本）
            output_path.mkdir(parents=True, exist_ok=True)
            
            if not input_path.exists():
                raise FileNotFoundError(f"输入目录不存在: {input_path}（请先运行下载脚本）")

            # 处理文件（适配下载脚本的命名规则 adblock01.txt, allow01.txt 等）
            self._process_file_group(input_path, 'adblock*.txt', False)
            self._process_file_group(input_path, 'allow*.txt', True)
            
            # 后处理
            self._post_process()
            
            # 保存结果
            self._save_rules(output_path)
            
            logging.info(f"合并完成 | 黑名单: {len(self.black_rules)}条 | 白名单: {len(self.white_rules)}条")
            return True

        except Exception as e:
            logging.critical(f"处理失败: {type(e).__name__}: {str(e)}")
            return False

    def _process_file_group(self, input_path: Path, pattern: str, is_whitelist: bool):
        """处理文件组（优化性能）"""
        for file in sorted(input_path.glob(pattern)):  # 按文件名排序处理
            try:
                self._process_single_file(file, is_whitelist)
            except Exception as e:
                logging.error(f"处理文件失败 {file.name}: {type(e).__name__}")

    def _process_single_file(self, file: Path, is_whitelist: bool):
        """处理单个文件（内存优化版）"""
        file_size = file.stat().st_size
        if file_size > self.config['max_file_size_mb'] * 1024 * 1024:
            logging.warning(f"文件过大({file_size/1024/1024:.1f}MB): {file.name}")
            return

        try:
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

        except Exception as e:
            logging.error(f"处理异常 {file.name}: {type(e).__name__}")
            raise

    def _process_line(self, line: str, is_whitelist: bool):
        """高效行处理（适配多来源规则）"""
        if not line:
            return

        # 快速注释检测
        if self._COMMENT_PATTERN.match(line):
            if not self.config['minify_output']:
                (self.white_rules if is_whitelist else self.black_rules).add(line)
            return

        # 规则匹配
        patterns = self._patterns['white' if is_whitelist else 'black']
        for pattern, processor in patterns:
            if match := pattern.match(line):
                target = self.white_rules if is_whitelist else self.black_rules
                target.add(processor(match) if processor else line)
                return

        # 未匹配处理（保留原始规则）
        if is_whitelist and line.startswith('@@'):
            self.white_rules.add(line)
        elif not is_whitelist:
            self.black_rules.add(line)

    def _post_process(self):
        """后处理（去重+冲突解决）"""
        if self.config['remove_duplicates']:
            self._optimized_dedupe()

    def _optimized_dedupe(self):
        """高性能去重"""
        def fingerprint(rule):
            return hashlib.md5(
                re.sub(r'\s+', '', rule.lower()).encode()
            ).hexdigest()

        # 生成指纹
        black_fps = {fingerprint(r) for r in self.black_rules 
                    if not r.startswith(('!', '['))}
        white_fps = {fingerprint(r[2:]) for r in self.white_rules 
                    if r.startswith('@@')}

        # 冲突解决
        if self.config['conflict_resolution'] == 'whitelist_priority':
            self.white_rules = {r for r in self.white_rules 
                              if not (r.startswith('@@') and fingerprint(r[2:]) in black_fps)}
        else:
            self.black_rules = {r for r in self.black_rules 
                              if fingerprint(r) not in white_fps}

    def _save_rules(self, output_dir: Path):
        """安全保存结果"""
        try:
            # 黑名单
            with NamedTemporaryFile('w', encoding='utf-8', delete=False) as tmp:
                tmp.writelines(f"{r}\n" for r in sorted(self.black_rules, key=str.lower))
                os.replace(tmp.name, output_dir / 'adblock.txt')

            # 白名单
            with NamedTemporaryFile('w', encoding='utf-8', delete=False) as tmp:
                tmp.writelines(f"{r}\n" for r in sorted(self.white_rules, key=str.lower))
                os.replace(tmp.name, output_dir / 'allow.txt')

            logging.info(f"规则已保存到: {output_dir}")

        except IOError as e:
            logging.error(f"写入失败: {type(e).__name__}")
            raise

if __name__ == '__main__':
    # 适配下载脚本的输出结构
    merger = RuleMerger(
        input_dir='./tmp',       # 下载脚本的输出目录
        output_dir='./data/rules',
        keep_hosts_syntax=False  # 将Hosts规则转为AdBlock格式
    )
    
    exit(0 if merger.process_files() else 1)