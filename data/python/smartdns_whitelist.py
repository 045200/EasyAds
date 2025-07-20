import re
from pathlib import Path

def convert_to_smartdns_whitelist(input_file: str, output_file: str) -> int:
    """
    Convert AdBlock whitelist rules to SmartDNS whitelist format.
    
    Args:
        input_file: Path to input AdBlock whitelist file
        output_file: Path to output SmartDNS whitelist file
    
    Returns:
        Number of whitelist rules generated
    
    Raises:
        FileNotFoundError: If input file does not exist
        IOError: If file operations fail
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    print("Generating SmartDNS whitelist rules...")
    
    domain_pattern = re.compile(r'@@\|\|([a-zA-Z0-9.-]+)\^')
    processed_domains = set()
    count = 0
    
    try:
        with input_path.open('r', encoding='utf-8', errors='ignore') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:
            
            # Write header
            outfile.write("# SmartDNS whitelist rules for GOODBYEADS\n")
            outfile.write("# Homepage: https://github.com/8680/GOODBYEADS\n")
            outfile.write("# Format: address /domain/-\n")
            outfile.write("# Generated from AdBlock whitelist rules\n\n")
            
            for line in infile:
                line = line.strip()
                match = domain_pattern.search(line)
                if match:
                    domain = match.group(1)
                    if domain not in processed_domains:
                        processed_domains.add(domain)
                        outfile.write(f"address /{domain}/-\n")
                        count += 1
                        
        print(f"Generated {count} SmartDNS whitelist rules")
        return count
        
    except IOError as e:
        print(f"Error processing files: {e}")
        return 0

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "data" / "rules" / "allow.txt"
    output_file = base_dir / "data" / "rules" / "smartdns-whitelist.conf"
    
    convert_to_smartdns_whitelist(input_file, output_file)