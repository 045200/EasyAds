#!/usr/bin/env python3
"""
GitHub Actions优化版规则合并脚本
特性：
1. 完全适配GitHub Actions环境
2. 增强的错误处理和日志输出
3. 高性能多线程处理
4. 安全的临时文件管理
"""

import re
import os
import time
import mmap
import logging
import hashlib
from pathlib import Path
from tempfile import NamedTemporaryFile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Tuple

class GitHubRuleMerger:
    __slots__ = ['black_rules', 'white_rules', '_patterns', 'config', '_logger']
    
    # GitHub Actions专用配置
    DEFAULT_CONFIG = {
        # 输入目录路径，支持环境变量注入
        # 默认值: './tmp'
        # 建议: 保持默认或设置为GitHub工作空间子目录
        'input_dir': os.getenv('INPUT_DIR', './tmp'),
        
        # 输出目录路径，支持环境变量注入
        # 默认值: './data/rules'
        # 建议: 设置为可持久化的目录
        'output_dir': os.getenv('OUTPUT_DIR', './data/rules'),
        
        # 是否保留原始hosts文件语法(如127.0.0.1 example.com)
        # 默认值: False (转换为AdBlock语法)
        # 建议: 仅在需要兼容旧系统时启用
        'keep_hosts_syntax': False,
        
        # 是否移除重复规则(基于BLAKE2哈希去重)
        # 默认值: True
        # 建议: 始终启用以提高规则质量
        'remove_duplicates': True,
        
        # 是否最小化输出(移除注释和空行)
        # 默认值: True
        # 建议: 生产环境启用，调试时禁用
        'minify_output': True,
        
        # 单个文件最大处理大小(MB)
        # 默认值: 50 (GitHub Actions内存限制考虑)
        # 警告: 超过此值将跳过处理
        'max_file_size_mb': 50,
        
        # 处理线程数(根据GitHub Actions机器配置优化)
        # 默认值: 4 (2vCPU环境最佳实践)
        # 范围: 1-8 (超过可能导致OOM)
        'worker_threads': 4,
        
        # 整体处理超时时间(秒)
        # 默认值: 300 (5分钟)
        # 建议: 复杂规则集可增至600
        'timeout': 300,
    }

    # 预编译正则（CI环境优化）
    _HOSTS_PATTERN = re.compile(r'^(?:127\.0\.0\.1|0\.0\.0\.0|::)\s+([\w.-]+)')
    _COMMENT_PATTERN = re.compile(r'^[![]')

    def __init__(self, **kwargs):
        """初始化CI优化处理器"""
        self.black_rules = set()
        self.white_rules = set()
        self.config = {**self.DEFAULT_CONFIG, **kwargs}
        self._logger = self._init_github_logger()
        self._compile_patterns()

    def _init_github_logger(self):
        """GitHub Actions友好的日志配置"""
        logger = logging.getLogger('gh_rule_merger')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '::%(levelname)s:: %(message)s'  # GitHub Actions专用格式
        ))
        logger.addHandler(handler)
        return logger

    def _compile_patterns(self):
        """线程安全的模式编译"""
        self._patterns = {
            'black': [
                (self._HOSTS_PATTERN, self._make_hosts_processor()),
                (re.compile(r'^\|\|([^\s\\\/]+)\^?$'), None),
                (re.compile(r'^\|\|([^\s\\\/]+)\^?\$[a-z-_,=]+'), None),
                (re.compile(r'^/.*/$'), None)
            ],
            'white': [
                (re.compile(r'^@@\|\|([^\s\\\/]+)\^?$'), None),
                # 修复的正则表达式：添加了缺失的闭合括号和完整匹配
                (re.compile(r'^@@\d+\.\d+\.\d+\.\d+\s+([\w.-]+)'), 
                 self._make_hosts_processor(white_list=True))
            ]
        }

    def _make_hosts_processor(self, white_list=False):
        """工厂方法创建处理器（避免lambda序列化问题）"""
        prefix = '@@' if white_list else ''
        keep_original = self.config['keep_hosts_syntax']
        
        def processor(match):
            return match.group(0) if keep_original else f"{prefix}||{match.group(1)}^"
        return processor

    def process_files(self) -> bool:
        """CI优化的主处理流程"""
        try:
            input_path = Path(self.config['input_dir']).absolute()
            output_path = Path(self.config['output_dir']).absolute()
            
            # CI环境目录验证
            if not input_path.exists():
                self._logger.error(f"::error::Input directory not found: {input_path}")
                return False

            output_path.mkdir(parents=True, exist_ok=True)
            
            # 多线程文件处理
            with ThreadPoolExecutor(max_workers=self.config['worker_threads']) as executor:
                futures = []
                futures.append(executor.submit(
                    self._process_file_group, input_path, 'adblock*.txt', False
                ))
                futures.append(executor.submit(
                    self._process_file_group, input_path, 'allow*.txt', True
                ))
                
                for future in as_completed(futures, timeout=self.config['timeout']):
                    if future.exception():
                        self._logger.error(f"::error::{future.exception()}")

            # 后处理
            self._post_process()
            
            # 原子写入
            self._atomic_write(output_path)
            
            self._logger.info(f"::notice::Merged {len(self.black_rules)} blacklist and {len(self.white_rules)} whitelist rules")
            return True

        except Exception as e:
            self._logger.critical(f"::error::Process failed: {type(e).__name__}: {str(e)}")
            return False

    def _process_file_group(self, input_path: Path, pattern: str, is_whitelist: bool):
        """线程安全文件组处理"""
        for file in sorted(input_path.glob(pattern)):
            try:
                self._process_single_file(file, is_whitelist)
            except Exception as e:
                self._logger.warning(f"::warning::Skipped {file.name}: {type(e).__name__}")

    def _process_single_file(self, file: Path, is_whitelist: bool):
        """安全文件处理（带资源清理）"""
        file_size = file.stat().st_size
        max_size = self.config['max_file_size_mb'] * 1024 * 1024

        if file_size > max_size:
            self._logger.warning(f"::warning::File too big {file.name} ({file_size/1024/1024:.1f}MB)")
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
                        except UnicodeDecodeError:
                            continue

        except mmap.error as e:
            self._logger.warning(f"::warning::MMap error {file.name}: {str(e)}")
            # 回退到普通读取
            with file.open('r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    self._process_line(line.strip(), is_whitelist)

    def _process_line(self, line: str, is_whitelist: bool):
        """高效行处理（线程安全）"""
        if not line or self._COMMENT_PATTERN.match(line):
            if not self.config['minify_output']:
                (self.white_rules if is_whitelist else self.black_rules).add(line)
            return

        target = self.white_rules if is_whitelist else self.black_rules
        patterns = self._patterns['white' if is_whitelist else 'black']

        for pattern, processor in patterns:
            if match := pattern.match(line):
                rule = processor(match) if processor else line
                target.add(rule)
                return

        if is_whitelist and line.startswith('@@'):
            self.white_rules.add(line)
        elif not is_whitelist:
            self.black_rules.add(line)

    def _post_process(self):
        """并行化后处理"""
        if self.config['remove_duplicates']:
            with ThreadPoolExecutor(max_workers=2) as executor:
                executor.submit(self._deduplicate, self.black_rules, False)
                executor.submit(self._deduplicate, self.white_rules, True)

    def _deduplicate(self, rules: Set[str], is_whitelist: bool):
        """BLAKE2去重算法"""
        seen = set()
        fingerprint = lambda r: hashlib.blake2b(
            r.lower().encode(), digest_size=16
        ).hexdigest()

        for rule in list(rules):
            fp = fingerprint(rule)
            if fp in seen or (is_whitelist and rule.startswith('@@') 
                             and fingerprint(rule[2:]) in seen):
                rules.discard(rule)
            else:
                seen.add(fp)

    def _atomic_write(self, output_dir: Path):
        """CI安全的原子写入"""
        try:
            # 黑名单
            with NamedTemporaryFile('w', encoding='utf-8', dir=output_dir, delete=False) as tmp:
                tmp.writelines(f"{r}\n" for r in sorted(self.black_rules, key=str.lower))
                os.chmod(tmp.name, 0o644)
                os.replace(tmp.name, output_dir / 'adblock.txt')

            # 白名单
            with NamedTemporaryFile('w', encoding='utf-8', dir=output_dir, delete=False) as tmp:
                tmp.writelines(f"{r}\n" for r in sorted(self.white_rules, key=str.lower))
                os.chmod(tmp.name, 0o644)
                os.replace(tmp.name, output_dir / 'allow.txt')

        finally:
            # CI环境清理
            if hasattr(self, '_temp_files'):
                for f in self._temp_files:
                    try:
                        os.unlink(f)
                    except:
                        pass

if __name__ == '__main__':
    start_time = time.monotonic()
    merger = GitHubRuleMerger()

    try:
        success = merger.process_files()
        elapsed = time.monotonic() - start_time
        merger._logger.info(f"::notice::Process completed in {elapsed:.2f}s")
        exit(0 if success else 1)
    except KeyboardInterrupt:
        merger._logger.error("::error::Process interrupted by user")
        exit(130)
    except Exception as e:
        merger._logger.critical(f"::error::Critical failure: {str(e)}")
        exit(1)