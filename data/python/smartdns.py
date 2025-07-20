import os
from pathlib import Path

def convert_to_smartdns_format(input_file: str, output_file: str) -> int:
    """
    Convert AdBlock rules to SmartDNS format.
    
    Args:
        input_file: Path to input AdBlock rules file
        output_file: Path to output SmartDNS rules file
    
    Returns:
        Number of rules generated
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    print("Generating SmartDNS rules...")
    
    generated_count = 0
    seen_domains = set()
    
    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:
            
            # Write header
            outfile.write("# SmartDNS rules for GOODBYEADS\n")
            outfile.write("# Homepage: https://github.com/8680/GOODBYEADS\n")
            outfile.write("# Format: address /domain/#\n\n")
            
            for line in infile:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('!'):
                    continue
                
                # Process AdBlock DNS rules
                if line.startswith("||") and line.endswith("^"):
                    domain = line[2:-1]
                    
                    # Skip wildcard domains and duplicates
                    if '*' not in domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        outfile.write(f"address /{domain}/#\n")
                        generated_count += 1
                        
        print(f"Generated {generated_count} SmartDNS rules")
        return generated_count
        
    except IOError as e:
        print(f"Error processing files: {e}")
        return 0

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "data" / "rules" / "dns.txt"
    output_file = base_dir / "data" / "rules" / "smartdns.conf"
    
    convert_to_smartdns_format(input_file, output_file)