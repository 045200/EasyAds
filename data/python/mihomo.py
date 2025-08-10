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

def process_domain_file(file_path, is_allow_list=False):
    """Process a single domain file and return cleaned domains"""
    domains = set()
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
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
                elif line.startswith("@@||") and line.endswith("^"):
                    domain = line[4:-1]
                else:
                    domain = line

                # For allow list, we don't add the +. prefix yet
                domains.add(domain)

        log(f"Processed {len(domains)} domains from {file_path}")
        return domains

    except Exception as e:
        error(f"Error processing {file_path}: {str(e)}")
        return set()

def merge_domain_lists(block_domains, allow_domains, output_file):
    """Merge and deduplicate domain lists, applying allow list rules"""
    try:
        # Remove allowed domains from block list
        final_domains = block_domains - allow_domains

        # Prepare the output with +. prefix
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(f"+.{domain}" for domain in sorted(final_domains)))

        log(f"Merged domain list created at {output_file}")
        log(f"Total domains: {len(final_domains)} (Blocked: {len(block_domains)}, Allowed: {len(allow_domains)})")
        return True

    except Exception as e:
        error(f"Error merging domain lists: {str(e)}")
        return False

def main():
    # Configuration - adjust these paths as needed
    SCRIPT_DIR = Path(__file__).parent
    MI_HOME = SCRIPT_DIR.parent  # Assuming script is in a subdirectory

    # Path configuration
    config = {
        "block_file": MI_HOME / "rules" / "adblock-filtered.txt",          # Block list file
        "merged_file": MI_HOME / "temp" / "domains.txt",      # Merged domain list
        "output_file": MI_HOME / "rules" / "mihomo.mrs",      # Final output file
        "tool_dir": MI_HOME / "tools"                        # Directory for Mihomo tool
    }

    # Create necessary directories
    for path in [config["merged_file"].parent, config["tool_dir"]]:
        path.mkdir(parents=True, exist_ok=True)

    # Step 1: Process block list
    block_domains = process_domain_file(config["block_file"])
    if not block_domains:
        error("No domains found in block list")
        sys.exit(1)

    # Step 2: Process allow list (if exists)
    allow_domains = set()
    if config["allow_file"].exists():
        allow_domains = process_domain_file(config["allow_file"], is_allow_list=True)
    else:
        log("No allow list found, proceeding without it")

    # Step 3: Merge and deduplicate domain lists
    if not merge_domain_lists(block_domains, allow_domains, config["merged_file"]):
        sys.exit(1)

    # Step 4: Download Mihomo tool if needed
    mihomo_tool = download_mihomo_tool(config["tool_dir"])
    if not mihomo_tool:
        sys.exit(1)

    # Step 5: Convert to mrs format
    if not convert_to_mrs(config["merged_file"], config["output_file"], mihomo_tool):
        sys.exit(1)

    log("Mihomo rules generation completed successfully")

if __name__ == "__main__":
    main()