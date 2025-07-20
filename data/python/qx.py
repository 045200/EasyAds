import os
from pathlib import Path

def replace_content_in_file(input_file: str, output_file: str) -> int:
    """
    Convert DNS rules to Quantumult X format and filter unwanted patterns.
    
    Args:
        input_file: Path to input DNS rules file
        output_file: Path to output Quantumult X rules file
    
    Returns:
        Number of rules processed
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    processed_count = 0
    
    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:
            
            for line in infile:
                line = line.strip()
                if not line or line.startswith('#'):
                    # Skip empty lines and comments
                    continue
                    
                if (':' not in line and '.js' not in line and '/' not in line and
                    line.startswith("||") and line.endswith("^")):
                    new_line = line.replace("||", "DOMAIN,").replace("^", ",reject")
                    outfile.write(new_line + '\n')
                    processed_count += 1
                    
        return processed_count
        
    except IOError as e:
        print(f"Error processing files: {e}")
        return 0

def remove_whitelist_domains(input_file: str, whitelist_file: str) -> int:
    """
    Remove whitelisted domains from the rules file.
    
    Args:
        input_file: Path to rules file to filter
        whitelist_file: Path to whitelist file
    
    Returns:
        Number of rules removed
    """
    input_path = Path(input_file)
    whitelist_path = Path(whitelist_file)
    
    if not input_path.exists() or not whitelist_path.exists():
        raise FileNotFoundError("Input or whitelist file not found")
    
    removed_count = 0
    
    try:
        # Read whitelist domains
        with whitelist_path.open('r', encoding='utf-8') as wfile:
            whitelist = {entry.strip()[4:-1] 
                        for entry in wfile 
                        if entry.strip().startswith('@@||') 
                        and entry.strip().endswith('^')}
        
        # Filter input file
        with input_path.open('r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        with input_path.open('w', encoding='utf-8') as outfile:
            for line in lines:
                domain = line.split(',')[1] if line.startswith('DOMAIN,') else None
                if domain and domain in whitelist:
                    removed_count += 1
                else:
                    outfile.write(line)
                    
        return removed_count
        
    except IOError as e:
        print(f"Error processing files: {e}")
        return 0

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "data" / "rules" / "dns.txt"
    output_file = base_dir / "data" / "rules" / "qx.list"
    whitelist_file = base_dir / "data" / "mod" / "whitelist.txt"
    
    processed = replace_content_in_file(input_file, output_file)
    removed = remove_whitelist_domains(output_file, whitelist_file)
    
    print(f"Processed {processed} rules, removed {removed} whitelisted domains")