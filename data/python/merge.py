import re
from pathlib import Path
from typing import List, Set

def merge_files(pattern: str, output_file: Path, encoding_fallback: bool = True) -> None:
    """Merge files matching pattern into a single output file with encoding fallback.
    
    Args:
        pattern: Glob pattern to match files
        output_file: Path to output file
        encoding_fallback: Whether to try latin-1 if UTF-8 fails
    """
    files = sorted(Path('tmp').glob(pattern))
    with open(output_file, 'w', encoding='utf-8') as out:
        for file in files:
            try:
                # First try UTF-8
                with open(file, 'r', encoding='utf-8') as f:
                    out.write(f.read())
            except UnicodeDecodeError:
                if encoding_fallback:
                    # Fallback to latin-1 if UTF-8 fails
                    with open(file, 'r', encoding='latin-1') as f:
                        out.write(f.read())
                else:
                    raise
            out.write('\n')

def clean_rules(input_file: Path, output_file: Path) -> None:
    """Clean rules by removing comments, invalid lines and normalizing Hosts entries.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(input_file, 'r', encoding='latin-1') as f:
            content = f.read()

    # Process content line by line
    cleaned_lines: List[str] = []
    
    for line in content.splitlines():
        original_line = line.strip()
        line = original_line
        
        # Skip empty lines
        if not line:
            continue
            
        # Handle Hosts format (127.0.0.1 domain.com)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+', line):
            # Convert Hosts format to AdBlock syntax
            domain = line.split()[1].strip()
            if not domain or domain.startswith('#'):
                continue
            line = f"||{domain}^"
        
        # Remove inline comments
        line = re.sub(r'\s*#.*$', '', line)
        
        # Skip comment lines and invalid rules
        if (line.startswith(('!', '#', '@@')) or 
            not line or 
            line.isspace() or
            '##' in line or 
            '#@#' in line or
            line.startswith('[')):  # Skip ABP-style element hiding
            continue
            
        # Basic validation for AdBlock rules
        if not is_valid_rule(line):
            continue
            
        cleaned_lines.append(line + '\n')

    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)

def is_valid_rule(rule: str) -> bool:
    """Check if a rule is a valid AdBlock rule or Hosts entry.
    
    Args:
        rule: The rule to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Skip empty rules
    if not rule or rule.isspace():
        return False
        
    # Basic pattern checks
    if (rule.startswith('||') and '^' in rule) or  # Domain rule
       (rule.startswith('|') and '|' in rule[1:]) or  # URL rule
       (rule.startswith('/') and rule.endswith('/')) or  # Regex rule
       ('*' in rule) or  # Wildcard rule
       (re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+', rule)):  # Hosts rule
        return True
        
    return False

def extract_allow_lines(allow_file: Path, adblock_combined_file: Path, allow_output_file: Path) -> None:
    """Extract allow rules (@ lines) from combined files.
    
    Args:
        allow_file: Path to allow rules file
        adblock_combined_file: Path to combined AdBlock rules file
        allow_output_file: Path to output allow rules file
    """
    # Read allow file with encoding fallback
    try:
        with open(allow_file, 'r', encoding='utf-8') as f:
            allow_lines = f.readlines()
    except UnicodeDecodeError:
        with open(allow_file, 'r', encoding='latin-1') as f:
            allow_lines = f.readlines()

    # Append to combined file
    with open(adblock_combined_file, 'a', encoding='utf-8') as out:
        out.writelines(allow_lines)

    # Extract @ lines and validate them
    try:
        with open(adblock_combined_file, 'r', encoding='utf-8') as f:
            lines = [line for line in f if line.startswith('@@') and is_valid_rule(line[2:].strip())]
    except UnicodeDecodeError:
        with open(adblock_combined_file, 'r', encoding='latin-1') as f:
            lines = [line for line in f if line.startswith('@@') and is_valid_rule(line[2:].strip())]

    # Write unique allow rules
    with open(allow_output_file, 'w', encoding='utf-8') as f:
        f.writelines(sorted(set(lines)))

def move_files_to_target(adblock_file: Path, allow_file: Path, target_dir: Path) -> None:
    """Move processed files to target directory.
    
    Args:
        adblock_file: Path to AdBlock rules file
        allow_file: Path to allow rules file
        target_dir: Path to target directory
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    adblock_target = target_dir / 'adblock.txt'
    allow_target = target_dir / 'allow.txt'

    adblock_file.replace(adblock_target)
    allow_file.replace(allow_target)

def deduplicate_txt_files(target_dir: Path) -> None:
    """Remove duplicate lines from all txt files in target directory.
    
    Args:
        target_dir: Path to target directory
    """
    for file in target_dir.glob('*.txt'):
        try:
            with open(file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            with open(file, 'r', encoding='latin-1') as f:
                lines = f.readlines()

        seen: Set[str] = set()
        unique_lines: List[str] = []
        
        for line in lines:
            stripped = line.strip()
            if stripped not in seen:
                seen.add(stripped)
                unique_lines.append(line)

        with open(file, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)

def main() -> None:
    """Main processing function."""
    # Create directories if they don't exist
    tmp_dir = Path('tmp')
    rules_dir = Path('data/rules')
    tmp_dir.mkdir(parents=True, exist_ok=True)
    rules_dir.mkdir(parents=True, exist_ok=True)

    print("Merging adblock rules...")
    merge_files('adblock*.txt', tmp_dir / 'combined_adblock.txt')
    clean_rules(tmp_dir / 'combined_adblock.txt', tmp_dir / 'cleaned_adblock.txt')
    print("Adblock rules merged successfully")

    print("Merging allow rules...")
    merge_files('allow*.txt', tmp_dir / 'combined_allow.txt')
    clean_rules(tmp_dir / 'combined_allow.txt', tmp_dir / 'cleaned_allow.txt')
    print("Allow rules merged successfully")

    print("Extracting allow rules...")
    extract_allow_lines(
        tmp_dir / 'cleaned_allow.txt',
        tmp_dir / 'combined_adblock.txt',
        tmp_dir / 'allow.txt'
    )

    print("Moving files to target directory...")
    move_files_to_target(
        tmp_dir / 'cleaned_adblock.txt',
        tmp_dir / 'allow.txt',
        rules_dir
    )

    print("Deduplicating files...")
    deduplicate_txt_files(rules_dir)
    print("Process completed successfully")

if __name__ == '__main__':
    main()