import re
from pathlib import Path
from typing import Set, List
from datetime import datetime, timezone

def is_valid_rule(rule: str) -> bool:
    """
    Performs a basic validation check on an AdBlock-style rule.
    
    Args:
        rule: The rule string to validate (without any '@@' prefix).
        
    Returns:
        bool: True if the rule appears to have a valid format, False otherwise.
    """
    # Skip empty or whitespace-only rules
    if not rule or rule.isspace():
        return False
        
    # Disallow rules that are just comments or cosmetic filters
    if rule.startswith(('!', '#')) or '##' in rule or '#@#' in rule:
        return False

    # Accept common AdBlock rule patterns
    if re.match(r'^(\|\||/|\*|[a-zA-Z0-9_.-]).*', rule):
        return True
        
    return False

def process_and_split_rules(input_file: Path, block_output_file: Path, allow_output_file: Path) -> None:
    """
    Reads a combined list of rules, cleans them, splits them into block and 
    allow files, and writes the deduplicated results.
    
    Args:
        input_file: Path to the combined source file.
        block_output_file: Path for the final blocklist file.
        allow_output_file: Path for the final allowlist file.
    """
    block_rules: Set[str] = set()
    allow_rules: Set[str] = set()

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        with open(input_file, 'r', encoding='latin-1') as f:
            lines = f.readlines()

    for line in lines:
        # Strip leading/trailing whitespace
        line = line.strip()

        # Skip empty lines, section headers, and full-line comments
        if not line or line.startswith(('!', '[', '# ')):
            continue

        # Convert Hosts format (e.g., "127.0.0.1 domain.com") to AdBlock syntax
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}\s+', line):
            parts = line.split()
            if len(parts) > 1:
                domain = parts[1].strip()
                # Ensure the domain is not a comment and is a valid hostname
                if domain and not domain.startswith('#') and re.match(r'^[a-zA-Z0-9_.-]+$', domain):
                    block_rules.add(f"||{domain}^")
            continue

        # Remove inline comments, but be careful with cosmetic filter syntax
        if '##' not in line and '#@#' not in line:
            line = re.sub(r'\s*#.*$', '', line)
            
        # Classify the rule
        if line.startswith('@@'):
            # This is an allow rule
            rule_part = line[2:].strip()
            if is_valid_rule(rule_part):
                allow_rules.add(line)
            else:
                print(f"Rejected allow rule: {line} (reason: invalid rule_part)")
        elif '##' in line or '#@#' in line or line.startswith(('#?#', '$', '$$')):
            # Skip cosmetic, element hiding, and scriptlet injection rules
            continue
        else:
            # Everything else is considered a block rule
            if is_valid_rule(line):
                block_rules.add(line)

    # Write the unique, sorted block rules to the output file with a header
    with open(block_output_file, 'w', encoding='utf-8') as f:
        f.write("! Title: EasyAds Combined Blocklist\n")
        f.write(f"! Last Updated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("! Expires: 1 day (update recommended)\n")
        f.write("! Homepage: https://github.com/EasyAds/EasyAds\n")
        f.write("!--------------------------------------------------!\n\n")
        f.writelines(sorted([rule + '\n' for rule in block_rules]))

    # Write the unique, sorted allow rules to the output file with a header
    with open(allow_output_file, 'w', encoding='utf-8') as f:
        f.write("! Title: EasyAds Combined Allowlist\n")
        f.write(f"! Last Updated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("!--------------------------------------------------!\n\n")
        if not allow_rules:
            f.write("! Note: No allow rules were found in the input\n")
        else:
            f.writelines(sorted([rule + '\n' for rule in allow_rules]))

def main() -> None:
    """Main function to run the entire processing workflow."""
    tmp_dir = Path('tmp')
    rules_dir = Path('data/rules')
    
    # Ensure directories exist
    tmp_dir.mkdir(parents=True, exist_ok=True)
    rules_dir.mkdir(parents=True, exist_ok=True)

    all_rules_file = tmp_dir / 'all_rules_combined.txt'

    print("Step 1: Merging all adblock and allow source files...")
    source_files: List[Path] = sorted(Path('tmp').glob('adblock*.txt')) + sorted(Path('tmp').glob('allow*.txt'))

    with open(all_rules_file, 'w', encoding='utf-8') as outfile:
        for file in source_files:
            if file.stat().st_size == 0:
                print(f"Warning: {file} is empty")
                continue
            try:
                with open(file, 'r', encoding='utf-8') as infile:
                    content = infile.read()
                    if not content.strip():
                        print(f"Warning: {file} contains no valid content")
                        continue
                    outfile.write(content)
            except UnicodeDecodeError:
                with open(file, 'r', encoding='latin-1') as infile:
                    content = infile.read()
                    if not content.strip():
                        print(f"Warning: {file} contains no valid content")
                        continue
                    outfile.write(content)
            outfile.write('\n')
        print(f"-> All source files merged into {all_rules_file}")

    # Check if merged file contains allow rules
    with open(all_rules_file, 'r', encoding='utf-8') as f:
        content = f.read()
        if '@@' not in content:
            print("Warning: No allow rules (starting with '@@') found in merged file")

    print("Step 2: Processing, splitting, and deduplicating rules...")
    blocklist_path = rules_dir / 'adblock.txt'
    allowlist_path = rules_dir / 'allow.txt'
    process_and_split_rules(all_rules_file, blocklist_path, allowlist_path)
    print(f"-> Blocklist created at {blocklist_path}")
    print(f"-> Allowlist created at {allowlist_path}")

    print("\nProcess completed successfully!")

if __name__ == '__main__':
    main()