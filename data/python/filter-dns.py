import os
from pathlib import Path

def filter_adblock_rules(input_path, output_path):
    """
    Filter AdBlock rules and write DNS rules format.
    
    Args:
        input_path (str/Path): Path to input AdBlock rules file
        output_path (str/Path): Path to output DNS rules file
    """
    input_path = Path(input_path)
    output_path = Path(output_path)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:
            
            # Write header
            outfile.write(f"# DNS rules extracted from {input_path.name}\n")
            outfile.write(f"# Generated on {datetime.datetime.now()}\n\n")
            
            count = 0
            for line in infile:
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    outfile.write(line + '\n')
                    count += 1
            
            print(f"Processed {count} DNS rules")
            
    except IOError as e:
        print(f"Error processing files: {e}")

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    input_file = base_dir / "data" / "rules" / "adblock.txt"
    output_file = base_dir / "data" / "rules" / "dns.txt"
    
    filter_adblock_rules(input_file, output_file)