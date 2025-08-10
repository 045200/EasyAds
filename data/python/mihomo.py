#!/usr/bin/env python3
import os
import sys
import urllib.request
import gzip
import shutil
from pathlib import Path
import subprocess
from datetime import datetime

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

def download_mihomo_tool(tool_dir):
    """下载最新版 Mihomo 转换工具"""
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        version_file = tool_dir / "version.txt"
        
        log("获取 Mihomo 最新版本...")
        urllib.request.urlretrieve(version_url, version_file)

        with open(version_file, 'r') as f:
            version = f.read().strip()

        tool_name = f"mihomo-linux-amd64-{version}"
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
        tool_gz_path = tool_dir / f"{tool_name}.gz"

        log(f"下载 Mihomo 工具 v{version}...")
        urllib.request.urlretrieve(tool_url, tool_gz_path)

        tool_path = tool_dir / tool_name
        with gzip.open(tool_gz_path, 'rb') as f_in:
            with open(tool_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        tool_path.chmod(0o755)
        version_file.unlink()
        tool_gz_path.unlink()

        log(f"工具已下载到: {tool_path}")
        return tool_path

    except Exception as e:
        error(f"工具下载失败: {str(e)}")
        return None

def convert_to_mrs(input_file, output_file, tool_path):
    """转换为 Mihomo 的 .mrs 格式"""
    try:
        cmd = [
            str(tool_path),
            "convert-ruleset",
            "domain",
            "text",
            str(input_file),
            str(output_file)
        ]
        
        log(f"正在转换: {input_file} → {output_file}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            log(f"成功生成: {output_file}")
            return True
        error(f"转换失败: {result.stderr}")
        return False

    except Exception as e:
        error(f"转换出错: {str(e)}")
        return False

def process_adguard_rules(input_path, output_path):
    """处理纯 AdGuard Home 黑名单语法"""
    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f_in, \
             open(output_path, 'w', encoding='utf-8') as f_out:

            for line in f_in:
                line = line.strip()
                if not line or line.startswith('!'):
                    continue

                # 处理 AdGuard Home 专有黑名单语法
                if line.startswith("||") and line.endswith("^"):
                    # 处理: ||domain^ → +.domain
                    f_out.write(f"+.{line[2:-1]}\n")
                elif line.startswith("0.0.0.0 "):
                    # 处理: 0.0.0.0 domain → +.domain
                    f_out.write(f"+.{line[8:]}\n")
                elif line.startswith("||"):
                    # 处理: ||domain.com → +.domain.com
                    f_out.write(f"+.{line[2:]}\n")
                elif line.startswith("."):
                    # 处理: .domain.com → +.domain.com
                    f_out.write(f"+.{line[1:]}\n")
                else:
                    # 普通域名直接添加前缀
                    f_out.write(f"+.{line}\n")

        log(f"已处理 {input_path} → {output_path}")
        return True

    except Exception as e:
        error(f"规则处理失败: {str(e)}")
        return False

def main():
    # 配置路径
    BASE_DIR = Path(__file__).parent.parent
    config = {
        "input": BASE_DIR / "rules" / "adblock-filtered.txt",  # 输入文件
        "temp": BASE_DIR / "temp" / "mihomo-temp.txt",        # 临时文件
        "output": BASE_DIR / "rules" / "mihomo-adblock.mrs",  # 输出文件
        "tool_dir": BASE_DIR / "tools"                       # 工具目录
    }

    # 创建目录
    config["temp"].parent.mkdir(parents=True, exist_ok=True)
    config["tool_dir"].mkdir(parents=True, exist_ok=True)

    # 1. 处理 AdGuard 规则
    if not process_adguard_rules(config["input"], config["temp"]):
        sys.exit(1)

    # 2. 下载转换工具
    tool = download_mihomo_tool(config["tool_dir"])
    if not tool:
        sys.exit(1)

    # 3. 转换为 .mrs 格式
    if not convert_to_mrs(config["temp"], config["output"], tool):
        sys.exit(1)

    log("AdGuard Home 黑名单转换完成！")

if __name__ == "__main__":
    main()