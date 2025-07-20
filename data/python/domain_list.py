import os
from pathlib import Path

def extract_domains(input_file, output_file):
    """
    Extract domains from AdBlock-style DNS rules file.
    
    Args:
        input_file (str): Path to input DNS rules file
        output_file (str): Path to output domain list file
    """
    print("Extracting domain list...")
    
    # Convert to Path objects for better path handling
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    try:
        with input_path.open('r', encoding='utf-8', errors='ignore') as infile:
            domains = []
            for line in infile:
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    domain = line[2:-1]
                    domains.append(domain)
                    
        with output_path.open('w', encoding='utf-8') as outfile:
            outfile.write("# GOODBYEADS Domain List\n")
            outfile.write("# Homepage: https://github.com/045200/GOODBYEADS\n")
            outfile.write("# Generated from GOODBYEADS DNS rules\n\n")
            outfile.write("\n".join(domains))
            
        print(f"Extracted {len(domains)} domains to domain list")
        
    except IOError as e:
        print(f"Error processing files: {e}")

# Example usage
if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "data" / "rules" / "dns.txt"
    output_file = base_dir / "data" / "rules" / "ad-domain.txt"
    
    extract_domains(input_file, output_file)