#!/usr/bin/env python3
"""
AdGuard规则转换工作流 (GitHub CI优化版)
• 输入: /ads.yaml (根目录)
• 输出: /data/adb.mrs
• 自动使用预置Mihomo二进制
• 每8小时检查更新 (通过GitHub Actions)
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime
import logging

# === 配置区 ===
MIHOMO_BIN = "/data/mihomo-linux-amd64"  # 预置二进制路径
INPUT_FILE = "ads.yaml"                  # 根目录输入文件
OUTPUT_FILE = "adb.mrs"            # 二进制规则输出

# === 日志设置 ===
def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(handler)
    return logger

log = setup_logger()

# === 路径处理 ===
def get_root_dir() -> Path:
    """定位到GitHub仓库根目录"""
    script_dir = Path(__file__).absolute().parent
    if script_dir.parts[-2:] == ('data', 'python'):
        return script_dir.parent.parent
    return script_dir.parent  # 默认返回上一级

# === 规则转换核心 ===
def convert_to_mrs(input_path: Path, output_path: Path) -> bool:
    """
    使用预置Mihomo二进制转换规则
    参数参考: https://github.com/MetaCubeX/mihomo/wiki/Command-Line-Arguments#convert-ruleset
    """
    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        "domain",           # 输入类型
        "binary",           # 输出二进制格式
        str(input_path),    # 输入文件
        str(output_path)    # 输出文件
    ]
    
    try:
        log.info(f"开始转换: {input_path} → {output_path}")
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=300  # 5分钟超时
        )
        
        if result.returncode == 0:
            log.info(f"成功生成MRS文件: {output_path}")
            return True
            
        log.error(f"转换失败: {result.stderr}")
        return False
        
    except subprocess.TimeoutExpired:
        log.error("转换超时 (超过5分钟)")
        return False
    except Exception as e:
        log.error(f"转换异常: {str(e)}")
        return False

# === 主流程 ===
def main() -> int:
    root_dir = get_root_dir()
    input_path = root_dir / INPUT_FILE
    output_path = Path(OUTPUT_FILE)
    
    # 路径验证
    log.info("="*50)
    log.info(f"根目录: {root_dir}")
    log.info(f"输入文件: {input_path}")
    log.info(f"输出文件: {output_path}")
    log.info("="*50)
    
    if not input_path.exists():
        log.error(f"输入文件不存在: {input_path}")
        return 1
    
    if not output_path.parent.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 直接转换YAML到MRS
    if not convert_to_mrs(input_path, output_path):
        return 1
    
    log.info("="*50)
    log.info("转换流程完成！")
    log.info(f"输出文件大小: {output_path.stat().st_size / 1024:.2f} KB")
    log.info("="*50)
    return 0

if __name__ == "__main__":
    sys.exit(main())