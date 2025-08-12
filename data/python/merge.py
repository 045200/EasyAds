import os
import re
import glob
from pathlib import Path
from typing import Optional, List, Set
from multiprocessing import Pool, cpu_count
from itertools import islice
import logging

# Configure logging for GitHub Actions
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

def ensure_directory_exists(directory: str) -> None:
    """Ensure target directory exists, create if not."""
    Path(directory).mkdir(parents=True, exist_ok=True)

def validate_rule(line: str) -> Optional[str]:
    """Validate rule for AdGuard Home (adblock, Hosts, or whitelist)."""
    line = line.strip()
    if not line:
        return None

    # Whitelist rules (@@ prefix)
    if line.startswith('@@'):
        adblock_part = line[2:].strip()
        if not adblock_part:
            logging.warning(f"Invalid whitelist rule: {line}")
            return None
        if re.match(r'^\|\|[\w\-\.]+(?:\^|\$[a-zA-Z,=]+)?$', adblock_part) or \
           re.match(r'^[\w\-\.]+##[\w\-\.\#\:\[\]\(\)]+$', adblock_part):
            return line
        logging.warning(f"Invalid whitelist rule: {line}")
        return None

    # Hosts rules (IPv4 or IPv6 + domain)
    hosts_pattern = r'^(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\s+[\w\-\.]+$'
    if re.match(hosts_pattern, line):
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            ip, domain = parts
            if (re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', ip) or 
                re.match(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$', ip)) and \
               re.match(r'^[\w\-\.]+$', domain):
                return line
        logging.warning(f"Invalid Hosts rule: {line}")
        return None

    # Adblock rules (including $ modifiers and CSS selectors)
    adblock_pattern = r'^(?:\||@@)?[\w\-\.]+(?:\^|\$[a-zA-Z,=]+)?$|^[\w\-\.]+##[\w\-\.\#\:\[\]\(\)]+$'
    if re.match(adblock_pattern, line):
        if '$' in line:
            modifiers = line.split('$')[-1].split(',')
            valid_modifiers = {'important', 'badfilter', 'app', 'client', 'domain', 'denyallow'}
            for mod in modifiers:
                mod_key = mod.split('=')[0]
                if mod_key and mod_key not in valid_modifiers and not mod_key.startswith(('domain=', 'denyallow=')):
                    logging.warning(f"Invalid adblock modifier: {line}")
                    return None
        return line

    logging.warning(f"Invalid rule: {line}")
    return None

def process_chunk(chunk: List[str]) -> List[str]:
    """Process a chunk of rules for validation and deduplication."""
    seen = set()
    valid_rules = []
    for line in chunk:
        validated = validate_rule(line)
        if validated and validated not in seen:
            seen.add(validated)
            valid_rules.append(validated)
    return valid_rules

def merge_files(file_pattern: str, output_file: str) -> None:
    """Merge and clean files matching the pattern."""
    try:
        file_list = glob.glob(file_pattern)
        if not file_list:
            logging.warning(f"No files found matching {file_pattern}")
            return

        with open(output_file, 'w', encoding='utf-8') as outfile:
            for file in file_list:
                try:
                    with open(file, 'r', encoding='utf-8') as infile:
                        content = infile.read()
                        # Clean comments and empty lines
                        content = re.sub(r'^[!].*$\n', '', content, flags=re.MULTILINE)
                        content = re.sub(r'^#(?!\s*#).*\n?', '', content, flags=re.MULTILINE)
                        content = re.sub(r'^\s*\n', '', content, flags=re.MULTILINE)
                        outfile.write(content + '\n')
                    logging.info(f"Processed {file} into {output_file}")
                except Exception as e:
                    logging.error(f"Failed to read {file}: {e}")
        logging.info(f"Merged and cleaned {file_pattern} to {output_file}")
    except Exception as e:
        logging.error(f"Failed to merge {file_pattern}: {e}")

def deduplicate_rules(input_adblock: str, input_allow: str, output_adblock: str, output_allow: str) -> None:
    """Deduplicate and validate rules, splitting into adblock and whitelist files."""
    try:
        # Collect all rules
        all_rules = []
        for file in [input_adblock, input_allow]:
            if os.path.exists(file):
                try:
                    with open(file, 'r', encoding='utf-8') as f:
                        all_rules.extend(line.strip() for line in f if line.strip())
                except Exception as e:
                    logging.error(f"Failed to read {file}: {e}")

        # Process rules in parallel
        chunk_size = 10000  # Adjust based on memory constraints
        num_cores = cpu_count()
        chunks = [all_rules[i:i + chunk_size] for i in range(0, len(all_rules), chunk_size)]

        with Pool(processes=num_cores) as pool:
            chunk_results = pool.map(process_chunk, chunks)

        # Flatten results and classify rules
        whitelist_rules = []
        hosts_rules = []
        adblock_rules = []
        seen = set()

        for chunk in chunk_results:
            for rule in chunk:
                if rule not in seen:
                    seen.add(rule)
                    if rule.startswith('@@'):
                        whitelist_rules.append(rule)
                    elif re.match(r'^(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\s+[\w\-\.]+$', rule):
                        hosts_rules.append(rule)
                    else:
                        adblock_rules.append(rule)

        # Sort rules by priority: whitelist > Hosts > adblock
        final_adblock_rules = whitelist_rules + hosts_rules + adblock_rules

        # Write adblock.txt
        with open(output_adblock, 'w', encoding='utf-8') as f:
            f.write('\n'.join(final_adblock_rules) + '\n')
        logging.info(f"Deduplicated rules saved to {output_adblock}")

        # Write allow.txt
        with open(output_allow, 'w', encoding='utf-8') as f:
            f.write('\n'.join(whitelist_rules) + '\n')
        logging.info(f"Whitelist rules saved to {output_allow}")

    except Exception as e:
        logging.error(f"Failed to deduplicate rules: {e}")

def main():
    # Set directories
    work_dir = 'tmp'
    target_dir = Path('../data/rules')

    try:
        os.makedirs(work_dir, exist_ok=True)
        os.chdir(work_dir)
    except Exception as e:
        logging.error(f"Failed to switch to {work_dir}: {e}")
        return

    # Merge adblock and allow rules
    logging.info("Merging upstream adblock rules")
    merge_files('adblock*.txt', 'combined_adblock.txt')

    logging.info("Merging upstream whitelist rules")
    merge_files('allow*.txt', 'combined_allow.txt')

    # Deduplicate and validate rules
    logging.info("Filtering and deduplicating rules")
    ensure_directory_exists(target_dir)
    deduplicate_rules(
        input_adblock='combined_adblock.txt',
        input_allow='combined_allow.txt',
        output_adblock=target_dir / 'adblock.txt',
        output_allow=target_dir / 'allow.txt'
    )

    # Clean up temporary files
    for file in ['combined_adblock.txt', 'combined_allow.txt']:
        if os.path.exists(file):
            try:
                os.remove(file)
                logging.info(f"Removed temporary file {file}")
            except Exception as e:
                logging.error(f"Failed to remove {file}: {e}")

if __name__ == '__main__':
    main()