import os
from pathlib import Path

def extract_domains_to_loon_rules(input_file, output_file):
    """
    Extract domains from AdBlock-style DNS rules file and convert to Loon rules.
    
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
            domains = []
            for line in infile:
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    domain = line[2:-1]
                    domains.append(domain)

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open('w', encoding='utf-8') as outfile:
            outfile.write("# Loon Rules Generated from GOODBYEADS\n")
            outfile.write("# Homepage: https://github.com/045200/GOODBYEADS\n")
            outfile.write("# Type: DOMAIN-SUFFIX\n\n")
            
            # Write Loon rules (DOMAIN-SUFFIX format)
            for domain in domains:
                # Skip IP addresses and invalid domains
                if not domain.replace('.', '').isalnum():
                    continue
                outfile.write(f"DOMAIN-SUFFIX,{domain},REJECT\n")

        print(f"Generated {len(domains)} Loon rules")

    except IOError as e:
        print(f"Error processing files: {e}")

# Example usage
if __name__ == "__main__":
    # Get the directory where this script is located
    script_dir = Path(__file__).parent

    # Calculate base directory (assuming script is in data/python/)
    base_dir = script_dir.parent

    # Construct correct file paths
    input_file = base_dir / "rules" / "dns.txt"
    output_file = base_dir / "rules" / "loon-rules.lpx"  # Changed output filename

    extract_domains_to_loon_rules(input_file, output_file)