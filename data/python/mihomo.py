#!/usr/bin/env python3
import os
import sys
import urllib.request
import gzip
import shutil
from pathlib import Path
import subprocess
from datetime import datetime
import tempfile

def log(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [INFO] {message}")

def error(message):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {message}", file=sys.stderr)

def download_mihomo_tool(tool_dir):
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        version_url = "https://github.com/MetaCubeX/mihomo/releases/latest/download/version.txt"
        version_file = tool_dir / "version.txt"
        
        log(f"获取 Mihomo 最新版本 ({version_url})...")
        urllib.request.urlretrieve(version_url, version_file)

        with open(version_file, 'r') as f:
            version = f.read().strip()

        tool_name = f"mihomo-linux-amd64-{version}"
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/latest/download/{tool_name}.gz"
        tool_gz_path = tool_dir / f"{tool_name}.gz"

        log(f"下载 Mihomo 工具 v{version} ({tool_url})...")
        urllib.request.urlretrieve(tool_url, tool_gz_path)

        tool_path = tool_dir / tool_name
        with gzip.open(tool_gz_path, 'rb') as f_in:
            with open(tool_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        tool_path.chmod(0o755)
        version_file.unlink(missing_ok=True)
        tool_gz_path.unlink(missing_ok=True)

        log(f"工具已下载到临时目录: {tool_path}")
        return tool_path

    except Exception as e:
        error(f"工具下载失败: {str(e)}")
        return None

def convert_to_mrs(input_file, output_file, tool_path):
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
            log(f"成功生成规则文件: {output_file}")
            return True
        
        error(f"转换失败: {result.stderr}")
        return False

    except subprocess.CalledProcessError as e:
        error(f"转换命令执行失败: {str(e)}\n错误输出: {e.stderr}")
        return False
    except Exception as e:
        error(f"转换过程中出错: {str(e)}")
        return False

def process_adguard_rules(input_path, output_path):
    try:
        processed_lines = 0
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f_in, \
             open(output_path, 'w', encoding='utf-8') as f_out:

            for line in f_in:
                line = line.strip()
                if not line or line.startswith('!'):
                    continue

                if line.startswith("||") and line.endswith("^"):
                    f_out.write(f"+.{line[2:-1]}\n")
                    processed_lines += 1
                elif line.startswith("0.0.0.0 "):
                    f_out.write(f"+.{line[8:]}\n")
                    processed_lines += 1
                elif line.startswith("||"):
                    f_out.write(f"+.{line[2:]}\n")
                    processed_lines += 1
                elif line.startswith("."):
                    f_out.write(f"+.{line[1:]}\n")
                    processed_lines += 1
                else:
                    f_out.write(f"+.{line}\n")
                    processed_lines += 1

        log(f"已处理 {processed_lines} 条规则: {input_path} → {output_path}")
        return True

    except Exception as e:
        error(f"规则处理失败: {str(e)}")
        return False

def main():
    try:
        # 修正路径获取方式（关键修改点）
        script_dir = Path(__file__).parent  # /data/python
        base_dir = script_dir.parent       # /data
        rules_dir = base_dir / "rules"     # /data/rules
        
        config = {
            "input": rules_dir / "adblock-filtered.txt",
            "temp": Path(tempfile.gettempdir()) / "mihomo.txt",
            "output": rules_dir / "adb.mrs",
            "tool_dir": Path(tempfile.gettempdir()) / "mihomo_tools"
        }

        # 调试输出路径信息
        log("="*50)
        log("路径验证信息：")
        log(f"脚本目录: {script_dir}")
        log(f"基础目录: {base_dir}")
        log(f"规则目录: {rules_dir}")
        log(f"输入文件: {config['input']}")
        log("="*50)

        if not config["input"].exists():
            error(f"输入文件不存在: {config['input']}")
            error(f"请确保前序脚本已生成: {config['input']}")
            sys.exit(1)

        if not process_adguard_rules(config["input"], config["temp"]):
            sys.exit(1)

        tool = download_mihomo_tool(config["tool_dir"])
        if not tool:
            sys.exit(1)

        if not convert_to_mrs(config["temp"], config["output"], tool):
            sys.exit(1)

        try:
            config["temp"].unlink(missing_ok=True)
            shutil.rmtree(config["tool_dir"], ignore_errors=True)
            log("已清理临时文件和目录")
        except Exception as e:
            error(f"清理临时文件时出错: {str(e)}")

        log("="*50)
        log("AdGuard Home 黑名单转换完成！")
        log(f"最终输出: {config['output']}")
        log("="*50)

    except Exception as e:
        error(f"主流程执行失败: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()