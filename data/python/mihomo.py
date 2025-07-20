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

def prepare_domain_file(source_file, output_txt_file):
    """Prepare domain file with +. prefix for Mihomo conversion"""
    try:
        source_path = Path(source_file)
        output_path = Path(output_txt_file)

        with source_path.open('r', encoding='utf-8', errors='ignore') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            domains = set()
            for line in infile:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle different rule formats
                if line.startswith("||") and line.endswith("^"):
                    domain = line[2:-1]
                elif line.startswith("."):
                    domain = line[1:]
                elif line.startswith("0.0.0.0 "):
                    domain = line[8:]
                else:
                    domain = line
                
                domains.add(domain)

            # Write with +. prefix
            outfile.write("\n".join(f"+.{domain}" for domain in sorted(domains)))
        
        log(f"Prepared domain file at {output_path}")
        return True

    except Exception as e:
        error(f"Error preparing domain file: {str(e)}")
        return False

def main():
    # Configuration - adjust these paths as needed
    SCRIPT_DIR = Path(__file__).parent
    MI_HOME = SCRIPT_DIR.parent  # Assuming script is in a subdirectory
    
    # Path configuration
    config = {
        "source_file": MI_HOME / "rules" / "dns.txt",          # Input rules file
        "intermedia