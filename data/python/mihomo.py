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
    """Download and extract the latest Mihomo tool"""
    try:
        tool_dir = Path(tool_dir)
        tool_dir.mkdir(parents=True, exist_ok=True)

        # Get latest version
        version_url = "https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/version.txt"
        version_file = tool_dir / "version.txt"

        log("Downloading Mihomo version info...")
        urllib.request.urlretrieve(version_url, version_file)

        with open(version_file, 'r') as f:
            version = f.read().strip()

        # Construct download URL
        tool_name = f"mihomo-linux-amd64-{version}"
        tool_gz = f"{tool_name}.gz"
        tool_url = f"https://github.com/MetaCubeX/mihomo/releases/download/Prerelease-Alpha/{tool_gz}"

        # Download the tool
        log(f"Downloading Mihomo tool {version}...")
        tool_gz_path = tool_dir / tool_gz
        urllib.request.urlretrieve(tool_url, tool_gz_path)

        # Extract the tool
        tool_path = tool_dir / tool_name
        with gzip.open(tool_gz_path, 'rb') as f_in:
            with open(tool_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Make executable
        tool_path.chmod(0o755)

        # Clean up
        version_file.unlink()
        tool_gz_path.unlink()

        log(f"Mihomo tool downloaded to {tool_path}")
        return tool_path

    except Exception as e:
        error(f"Failed to download Mihomo tool: {str(e)}")
        return None

def convert_to_mrs(input_file, output_file, mihomo_tool_path):
    """Convert domain list to Mihomo .mrs format"""
    try:
        input_path = Path(input_file)
        output_path = Path(output_file)
        mihomo_tool = Path(mihomo_tool_path)

        # Validate files
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        if not mihomo_tool.exists():
            raise FileNotFoundError(f"Mihomo tool not found: {mihomo_tool}")

        # Prepare the output directory
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Execute the conversion command
        cmd = [
            str(mihomo_tool),
            "convert-ruleset",
            "domain",
            "text",
            str(input_path),
            str(output_path)
        ]

        log(f"Converting {input_path} to {output_path}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)

        if result.returncode == 0:
            log(f"Successfully created {output_path}")
            return True
        else:
            error(f"Conversion failed: {result.stderr}")
            return False

    except subprocess.CalledProcessError as e:
        error(f"Mihomo conversion error: {e.stderr}")
        return False
    except Exception as e:
        error(f"Conversion error: {str(e)}")
        return False

def prepare_blacklist(input_file, output_file):
    """Prepare pre-filtered blacklist for Mihomo"""
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f_in, \
             open(output_file, 'w', encoding='utf-8') as f_out:

            for line in f_in:
                line = line.strip()
                if not line or line.startswith(('!', '#')):
                    continue  # Skip comments and empty lines

                # Handle pure blacklist rules (no whitelist entries)
                if line.startswith("||") and line.endswith("^"):
                    # Convert ||domain^ to +.domain
                    domain = line[2:-1]
                    f_out.write(f"+.{domain}\n")
                elif line.startswith("0.0.0.0 "):
                    # Convert 0.0.0.0 domain to +.domain
                    domain = line[8:]
                    if not domain.startswith((' ', '#')):  # Skip malformed lines
                        f_out.write(f"+.{domain}\n")
                elif line.startswith("||"):
                    # Convert ||domain.com to +.domain.com
                    domain = line[2:]
                    f_out.write(f"+.{domain}\n")
                elif line.startswith("."):
                    # Convert .domain.com to +.domain.com
                    domain = line[1:]
                    f_out.write(f"+.{domain}\n")
                else:
                    # Plain domain, add +. prefix if not already present
                    if not line.startswith('+.'):
                        f_out.write(f"+.{line}\n")
                    else:
                        f_out.write(f"{line}\n")

        log(f"Blacklist prepared and saved to {output_file}")
        return True

    except Exception as e:
        error(f"Error preparing blacklist: {str(e)}")
        return False

def main():
    # Configuration
    SCRIPT_DIR = Path(__file__).parent
    MI_HOME = SCRIPT_DIR.parent  # Assuming script is in a subdirectory

    # Path configuration
    config = {
        "input_file": MI_HOME / "rules" / "adblock-filtered.txt",  # Pre-filtered blacklist
        "processed_file": MI_HOME / "temp" / "mihomo-ready.txt",   # Processed file
        "output_file": MI_HOME / "rules" / "mihomo.mrs",          # Final output
        "tool_dir": MI_HOME / "tools"                            # Mihomo tool dir
    }

    # Create necessary directories
    for path in [config["processed_file"].parent, config["tool_dir"]]:
        path.mkdir(parents=True, exist_ok=True)

    # Step 1: Prepare the pre-filtered blacklist
    if not prepare_blacklist(config["input_file"], config["processed_file"]):
        sys.exit(1)

    # Step 2: Download Mihomo tool if needed
    mihomo_tool = download_mihomo_tool(config["tool_dir"])
    if not mihomo_tool:
        sys.exit(1)

    # Step 3: Convert to mrs format
    if not convert_to_mrs(config["processed_file"], config["output_file"], mihomo_tool):
        sys.exit(1)

    log("Blacklist conversion completed successfully")

if __name__ == "__main__":
    main()