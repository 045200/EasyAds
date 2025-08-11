import re
from pathlib import Path
import logging
from typing import List, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Supported encodings to try (in order)
ENCODINGS = ['utf-8', 'utf-16', 'latin-1', 'iso-8859-1', 'cp1252']

class RuleProcessor:
    def __init__(self):
        self.tmp_dir = Path('tmp')
        self.rules_dir = Path('data/rules')
        self._create_directories()

    def _create_directories(self):
        """Create necessary directories if they don't exist."""
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    def _read_file(self, file_path: Path) -> str:
        """Read a file with encoding fallback."""
        for encoding in ENCODINGS:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        raise UnicodeDecodeError(f"Could not decode {file_path} with any of the supported encodings")

    def _write_file(self, file_path: Path, content: str):
        """Write content to a file with UTF-8 encoding."""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def merge_files(self, pattern: str, output_file: str, keep_comments: bool = False):
        """Merge files matching pattern into a single output file."""
        files = sorted(self.tmp_dir.glob(pattern))
        if not files:
            logger.warning(f"No files found matching pattern: {pattern}")
            return

        merged_content = []
        for file in files:
            try:
                content = self._read_file(file)
                if not keep_comments:
                    content = self._remove_comments(content)
                merged_content.append(content)
            except Exception as e:
                logger.error(f"Error processing {file}: {str(e)}")
                continue

        output_path = self.tmp_dir / output_file
        self._write_file(output_path, '\n'.join(merged_content))
        logger.info(f"Merged {len(files)} files into {output_path}")

    def _remove_comments(self, content: str) -> str:
        """Remove comment lines while preserving valid rules."""
        # Remove full-line comments (starting with ! or #)
        content = re.sub(r'^[!#].*$\n?', '', content, flags=re.MULTILINE)
        # Remove end-of-line comments (but preserve the rule)
        content = re.sub(r'\s*#[^#].*$', '', content, flags=re.MULTILINE)
        return content.strip()

    def clean_rules(self, input_file: str, output_file: str):
        """Clean and normalize rules."""
        input_path = self.tmp_dir / input_file
        try:
            content = self._read_file(input_path)
            
            # Normalize line endings and remove empty lines
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            
            # Remove invalid rules
            valid_lines = []
            for line in lines:
                if self._is_valid_rule(line):
                    valid_lines.append(line)
            
            output_path = self.tmp_dir / output_file
            self._write_file(output_path, '\n'.join(valid_lines))
            logger.info(f"Cleaned rules saved to {output_path}")
        except Exception as e:
            logger.error(f"Error cleaning rules: {str(e)}")
            raise

    def _is_valid_rule(self, line: str) -> bool:
        """Check if a line is a valid rule."""
        # Skip empty lines and comments (should already be handled)
        if not line or line.startswith(('!', '#')):
            return False
            
        # Basic validation for different rule types
        if line.startswith(('||', '@@', '||', '##', '#@#', '#$#')):
            return True
        if re.match(r'^[\w\-\.]+$', line):  # Simple domain rule
            return True
        if re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):  # Hosts rule
            return True
            
        # More complex rules with special characters
        if re.search(r'[/\$\,\^\=\~]', line):
            return True
            
        logger.warning(f"Potentially invalid rule: {line}")
        return True  # Keep by default, but log warning

    def extract_allow_rules(self, allow_file: str, adblock_combined_file: str, allow_output_file: str):
        """Extract and process allow rules."""
        try:
            # Read allow file
            allow_path = self.tmp_dir / allow_file
            allow_content = self._read_file(allow_path)
            allow_lines = [line.strip() for line in allow_content.splitlines() if line.strip()]
            
            # Append to combined file
            combined_path = self.tmp_dir / adblock_combined_file
            if combined_path.exists():
                combined_content = self._read_file(combined_path)
                combined_lines = combined_content.splitlines()
                combined_lines.extend(allow_lines)
                self._write_file(combined_path, '\n'.join(combined_lines))
            
            # Extract @@ rules and exceptions
            allow_rules = set()
            for line in allow_lines:
                if line.startswith('@@') or line.startswith('#@#') or '##@#' in line:
                    allow_rules.add(line)
                elif line.startswith('!'):
                    continue  # Skip comments
                elif 'domain=' in line or '$domain=' in line:
                    allow_rules.add(line)
            
            # Write unique allow rules
            allow_output_path = self.tmp_dir / allow_output_file
            self._write_file(allow_output_path, '\n'.join(sorted(allow_rules)))
            logger.info(f"Extracted {len(allow_rules)} allow rules to {allow_output_path}")
        except Exception as e:
            logger.error(f"Error extracting allow rules: {str(e)}")
            raise

    def move_files_to_target(self, adblock_file: str, allow_file: str):
        """Move processed files to target directory."""
        try:
            adblock_source = self.tmp_dir / adblock_file
            allow_source = self.tmp_dir / allow_file
            
            adblock_target = self.rules_dir / 'adblock.txt'
            allow_target = self.rules_dir / 'allow.txt'
            
            if adblock_source.exists():
                adblock_source.replace(adblock_target)
            if allow_source.exists():
                allow_source.replace(allow_target)
                
            logger.info(f"Moved files to {self.rules_dir}")
        except Exception as e:
            logger.error(f"Error moving files: {str(e)}")
            raise

    def deduplicate_files(self):
        """Remove duplicate lines from all txt files in target directory."""
        try:
            for file in self.rules_dir.glob('*.txt'):
                content = self._read_file(file)
                lines = content.splitlines()
                
                # Use ordered dict to preserve order while removing duplicates
                unique_lines = []
                seen = set()
                for line in lines:
                    normalized = self._normalize_rule(line)
                    if normalized not in seen:
                        seen.add(normalized)
                        unique_lines.append(line)
                
                if len(unique_lines) != len(lines):
                    self._write_file(file, '\n'.join(unique_lines))
                    logger.info(f"Removed {len(lines) - len(unique_lines)} duplicates from {file.name}")
        except Exception as e:
            logger.error(f"Error deduplicating files: {str(e)}")
            raise

    def _normalize_rule(self, rule: str) -> str:
        """Normalize a rule for duplicate checking."""
        # Remove leading/trailing whitespace
        rule = rule.strip()
        
        # For rules with options, sort the options for consistent comparison
        if '$' in rule:
            parts = rule.split('$')
            base = parts[0]
            options = sorted(option.strip() for option in parts[1].split(','))
            return f"{base}${','.join(options)}"
        
        return rule

    def process_rules(self):
        """Main processing pipeline."""
        try:
            logger.info("Starting rule processing...")
            
            # Step 1: Merge and clean adblock rules
            self.merge_files('adblock*.txt', 'combined_adblock.txt')
            self.clean_rules('combined_adblock.txt', 'cleaned_adblock.txt')
            
            # Step 2: Merge and clean allow rules
            self.merge_files('allow*.txt', 'combined_allow.txt', keep_comments=True)
            self.clean_rules('combined_allow.txt', 'cleaned_allow.txt')
            
            # Step 3: Extract allow rules
            self.extract_allow_rules(
                'cleaned_allow.txt',
                'combined_adblock.txt',
                'allow.txt'
            )
            
            # Step 4: Move to target directory
            self.move_files_to_target('cleaned_adblock.txt', 'allow.txt')
            
            # Step 5: Deduplicate
            self.deduplicate_files()
            
            logger.info("Rule processing completed successfully")
        except Exception as e:
            logger.error(f"Rule processing failed: {str(e)}")
            raise

if __name__ == '__main__':
    processor = RuleProcessor()
    processor.process_rules()