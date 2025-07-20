import os
import re
from pathlib import Path

def extract_to_loon_rules(input_file, output_file):
    """
    Extract rules from AdBlock-style DNS rules file and convert to Loon rules.
    
    Args:
        input_file (str): Path to input DNS rules file
        output_file (str): Path to output Loon rules file
    """
    print("Generating Loon rules from domain list...")

    # Convert to Path objects for better path handling
    input_path = Path(input_file)
    output_path = Path(output_file)

    # Debug print to show the actual path being checked
    print(f"Looking for input file at: {input_path}")
    print(f"Absolute input path: {input_path.absolute()}")

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    try:
        with input_path.open('r', encoding='utf-8', errors='ignore') as infile:
            ip_rules = []
            domain_rules = []
            domain_suffix_rules = []
            domain_keyword_rules = []
            
            ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?$')
            
            for line in infile:
                line = line.strip()
                if not line or line.startswith('!'):
                    continue
                
                # Handle IP-CIDR rules
                if line.startswith("||") and line.endswith("^"):
                    rule = line[2:-1]
                    if ip_pattern.match(rule.split('/')[0]):
                        ip_rules.append(f"IP-CIDR,{rule},REJECT,no-resolve")
                    else:
                        domain_suffix_rules.append(f"DOMAIN-SUFFIX,{rule},REJECT")
                
                # Handle direct domain rules (without wildcards)
                elif line.startswith("|http://") or line.startswith("|https://"):
                    domain = line.split('://')[1].split('^')[0].split('/')[0]
                    domain_rules.append(f"DOMAIN,{domain},REJECT")
                
                # Handle domain keyword rules (could be improved with more patterns)
                elif '*' in line:
                    keyword = line.replace('*', '').replace('^', '').replace('||', '')
                    if keyword:
                        domain_keyword_rules.append(f"DOMAIN-KEYWORD,{keyword},REJECT")

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open('w', encoding='utf-8') as outfile:
            outfile.write("# Loon Rules Generated from GOODBYEADS\n")
            outfile.write("# Homepage: https://github.com/045200/GOODBYEADS\n")
            outfile.write("# Updated: " + str(Path(__file__).stat().st_mtime) + "\n\n")
            
            # Write IP rules first
            if ip_rules:
                outfile.write("# IP Rules\n")
                outfile.write("\n".join(sorted(set(ip_rules))) + "\n\n")
            
            # Write domain rules
            if domain_rules:
                outfile.write("# Domain Rules\n")
                outfile.write("\n".join(sorted(set(domain_rules))) + "\n\n")
            
            # Write domain suffix rules
            if domain_suffix_rules:
                outfile.write("# Domain Suffix Rules\n")
                outfile.write("\n".join(sorted(set(domain_suffix_rules))) + "\n\n")
            
            # Write domain keyword rules
            if domain_keyword_rules:
                outfile.write("# Domain Keyword Rules\n")
                outfile.write("\n".join(sorted(set(domain_keyword_rules))) + "\n")

        total_rules = len(ip_rules) + len(domain_rules) + len(domain_suffix_rules) + len(domain_keyword_rules)
        print(f"Generated {total_rules} Loon rules (IP: {len(ip_rules)}, DOMAIN: {len(domain_rules)}, "
              f"SUFFIX: {len(domain_suffix_rules)}, KEYWORD: {len(domain_keyword_rules)})")

    except Exception as e:
        print(f"Error processing files: {e}")
        raise

# Example usage
if __name__ == "__main__":
    # Get the directory where this script is located
    script_dir = Path(__file__).parent

    # Calculate base directory (assuming script is in data/python/)
    base_dir = script_dir.parent

    # Construct correct file paths
    input_file = base_dir / "rules" / "dns.txt"
    output_file = base_dir / "rules" / "loon-rules.list"  # Changed to .list suffix

    extract_to_loon_rules(input_file, output_file)