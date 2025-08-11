import re
from pathlib import Path
from typing import List, Set

def merge_files(pattern: str, output_file: Path, encoding_fallback: bool = True) -> None:
    """Merge files matching pattern into a single output file with encoding fallback.
    
    Args:
        pattern: Glob pattern to match files.
        output_file: Path to the output file.
        encoding_fallback: Whether to try latin-1 if UTF-8 fails.
    """
    # Find all files in the 'tmp' directory matching the provided pattern
    files = sorted(Path('tmp').glob(pattern))
    
    # Open the output file in write mode with UTF-8 encoding
    with open(output_file, 'w', encoding='utf-8') as out:
        for file in files:
            try:
                # First, attempt to read the file with UTF-8 encoding
                with open(file, 'r', encoding='utf-8') as f:
                    out.write(f.read())
            except UnicodeDecodeError:
                if encoding_fallback:
                    # If UTF-8 fails, fallback to latin-1 encoding
                    with open(file, 'r', encoding='latin-1') as f:
                        out.write(f.read())
                else:
                    # If fallback is disabled, re-raise the exception
                    raise
            # Add a newline to separate content from different files
            out.write('\n')

def clean_rules(input_file: Path, output_file: Path) -> None:
    """Clean rules by removing comments, invalid lines, and normalizing Hosts entries.
    
    Args:
        input_file: Path to the input file.
        output_file: Path to the output file.
    """
    try:
        # Attempt to read the input file with UTF-8 encoding
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Fallback to latin-1 if UTF-8 decoding fails
        with open(input_file, 'r', encoding='latin-1') as f:
            content = f.read()

    cleaned_lines: List[str] = []
    
    # Process the content line by line
    for line in content.splitlines():
        line = line.strip()
        
        # Skip empty or blank lines
        if not line:
            continue
            
        # Handle Hosts format (e.g., "127.0.0.1 domain.com")
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+', line):
            parts = line.split()
            # Ensure there is a domain part and it's not a comment
            if len(parts) > 1 and not parts[1].startswith('#'):
                domain = parts[1].strip()
                # Convert to AdBlock syntax
                line = f"||{domain}^"
            else:
                continue
        
        # Remove any inline comments (e.g., "||domain.com^ # blocks ads")
        line = re.sub(r'\s*#.*$', '', line)
        
        # Skip comment lines, allow rules, and other invalid/unsupported formats
        if (line.startswith(('!', '#', '@@')) or 
            not line or 
            line.isspace() or
            '##' in line or  # Skip element hiding rules
            '#@#' in line or # Skip cosmetic filtering rules
            line.startswith('[')):  # Skip ABP-style section headers
            continue
            
        # Validate that the line is a potentially valid rule
        if not is_valid_rule(line):
            continue
            
        cleaned_lines.append(line + '\n')

    # Write the cleaned lines to the output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.writelines(cleaned_lines)

def is_valid_rule(rule: str) -> bool:
    """Check if a rule is a valid AdBlock rule.
    
    Args:
        rule: The rule to validate.
        
    Returns:
        bool: True if valid, False otherwise.
    """
    # Skip empty or whitespace-only rules
    if not rule or rule.isspace():
        return False
        
    # Basic pattern checks for common AdBlock syntax.
    # A rule is considered valid if it matches any of these patterns.
    is_domain_rule = rule.startswith('||') and '^' in rule
    is_url_rule = rule.startswith('|') and '|' in rule[1:]
    is_regex_rule = rule.startswith('/') and rule.endswith('/')
    has_wildcard = '*' in rule
    
    if is_domain_rule or is_url_rule or is_regex_rule or has_wildcard:
        return True
        
    # A simple check for a domain name without special characters can also be valid
    # This regex checks for a valid hostname format.
    if re.match(r'^[a-zA-Z0-9.-]+$', rule):
        return True

    return False

def extract_allow_lines(allow_file: Path, adblock_combined_file: Path, allow_output_file: Path) -> None:
    """Extract allow rules (lines starting with @@) from files.
    
    Args:
        allow_file: Path to a file containing additional allow rules.
        adblock_combined_file: Path to the combined AdBlock rules file.
        allow_output_file: Path to the output file for final allow rules.
    """
    # Read allow lines from the dedicated allow file with encoding fallback
    try:
        with open(allow_file, 'r', encoding='utf-8') as f:
            allow_lines = f.readlines()
    except UnicodeDecodeError:
        with open(allow_file, 'r', encoding='latin-1') as f:
            allow_lines = f.readlines()

    # Append these allow lines to the main combined file for unified processing
    with open(adblock_combined_file, 'a', encoding='utf-8') as out:
        out.writelines(allow_lines)

    # Now, extract all valid allow rules (starting with '@@') from the combined file
    all_lines: List[str] = []
    try:
        with open(adblock_combined_file, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
    except UnicodeDecodeError:
        with open(adblock_combined_file, 'r', encoding='latin-1') as f:
            all_lines = f.readlines()
            
    # Filter for lines that are valid allow rules
    valid_allow_lines = [
        line for line in all_lines 
        if line.startswith('@@') and is_valid_rule(line.strip()[2:])
    ]

    # Write the unique, sorted allow rules to the output file
    with open(allow_output_file, 'w', encoding='utf-8') as f:
        f.writelines(sorted(set(valid_allow_lines)))

def move_files_to_target(adblock_file: Path, allow_file: Path, target_dir: Path) -> None:
    """Move processed files to the final target directory.
    
    Args:
        adblock_file: Path to the processed AdBlock rules file.
        allow_file: Path to the processed allow rules file.
        target_dir: Path to the target directory.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    adblock_target = target_dir / 'adblock.txt'
    allow_target = target_dir / 'allow.txt'

    # Atomically move/rename the files to their final destination
    adblock_file.replace(adblock_target)
    allow_file.replace(allow_target)

def deduplicate_txt_files(target_dir: Path) -> None:
    """Remove duplicate lines from all .txt files in a directory.
    
    Args:
        target_dir: Path to the target directory containing .txt files.
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
        
        # Iterate through lines and keep only the first occurrence
        for line in lines:
            stripped_line = line.strip()
            if stripped_line and stripped_line not in seen:
                seen.add(stripped_line)
                unique_lines.append(line)

        # Overwrite the file with the unique lines
        with open(file, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)

def main() -> None:
    """Main processing function to run the entire workflow."""
    # Define directory paths
    tmp_dir = Path('tmp')
    rules_dir = Path('data/rules')
    
    # Ensure directories exist
    tmp_dir.mkdir(parents=True, exist_ok=True)
    rules_dir.mkdir(parents=True, exist_ok=True)

    print("Step 1: Merging and cleaning adblock rules...")
    merge_files('adblock*.txt', tmp_dir / 'combined_adblock.txt')
    clean_rules(tmp_dir / 'combined_adblock.txt', tmp_dir / 'cleaned_adblock.txt')
    print("-> Adblock rules processed successfully.")

    print("Step 2: Merging and cleaning allow rules...")
    merge_files('allow*.txt', tmp_dir / 'combined_allow.txt')
    clean_rules(tmp_dir / 'combined_allow.txt', tmp_dir / 'cleaned_allow.txt')
    print("-> Allow rules processed successfully.")

    print("Step 3: Extracting and finalizing allow rules...")
    extract_allow_lines(
        tmp_dir / 'cleaned_allow.txt',
        tmp_dir / 'cleaned_adblock.txt', # Use cleaned adblock file
        tmp_dir / 'allow.txt'
    )
    print("-> Allow rules extracted successfully.")

    print("Step 4: Moving final files to target directory...")
    move_files_to_target(
        tmp_dir / 'cleaned_adblock.txt',
        tmp_dir / 'allow.txt',
        rules_dir
    )
    print(f"-> Files moved to {rules_dir}")

    print("Step 5: Deduplicating final rule files...")
    deduplicate_txt_files(rules_dir)
    print("-> Deduplication complete.")
    
    print("\nProcess completed successfully!")

if __name__ == '__main__':
    main()

