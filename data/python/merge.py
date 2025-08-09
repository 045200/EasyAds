import re
from pathlib import Path

def merge_files(pattern, output_file):
    """Merge files matching pattern into a single output file with encoding fallback."""
    files = sorted(Path('tmp').glob(pattern))
    with open(output_file, 'w', encoding='utf-8') as out:
        for file in files:
            try:
                # First try UTF-8
                with open(file, 'r', encoding='utf-8') as f:
                    out.write(f.read())
            except UnicodeDecodeError:
                # Fallback to latin-1 if UTF-8 fails
                with open(file, 'r', encoding='latin-1') as f:
                    out.write(f.read())
            out.write('\n')

def clean_rules(input_file, output_file):
    """Clean rules by removing comments and invalid lines."""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(input_file, 'r', encoding='latin-1') as f:
            content = f.read()
    
    # Remove comment lines
    content = re.sub(r'^[!].*$\n', '', content, flags=re.MULTILINE)
    content = re.sub(r'^#(?!\s*#).*$\n?', '', content, flags=re.MULTILINE)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

def extract_allow_lines(allow_file, adblock_combined_file, allow_output_file):
    """Extract allow rules (@ lines) from combined files."""
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
    
    # Extract @ lines
    try:
        with open(adblock_combined_file, 'r', encoding='utf-8') as f:
            lines = [line for line in f if line.startswith('@')]
    except UnicodeDecodeError:
        with open(adblock_combined_file, 'r', encoding='latin-1') as f:
            lines = [line for line in f if line.startswith('@')]
    
    # Write unique allow rules
    with open(allow_output_file, 'w', encoding='utf-8') as f:
        f.writelines(sorted(set(lines)))

def move_files_to_target(adblock_file, allow_file, target_dir):
    """Move processed files to target directory."""
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    
    adblock_target = target_dir / 'adblock.txt'
    allow_target = target_dir / 'allow.txt'
    
    Path(adblock_file).rename(adblock_target)
    Path(allow_file).rename(allow_target)

def deduplicate_txt_files(target_dir):
    """Remove duplicate lines from all txt files in target directory."""
    target_dir = Path(target_dir)
    for file in target_dir.glob('*.txt'):
        try:
            with open(file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            with open(file, 'r', encoding='latin-1') as f:
                lines = f.readlines()
        
        seen = set()
        unique_lines = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                unique_lines.append(line)
        
        with open(file, 'w', encoding='utf-8') as f:
            f.writelines(unique_lines)

def main():
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