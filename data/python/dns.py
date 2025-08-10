import re
import time
import sqlite3
import tldextract
import subprocess
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Default configuration
DEFAULT_CONFIG = {
    'input_dir': Path('tmp'),
    'cache_db': Path('tmp/dns_cache.db'),
    'timeout': 2,
    'batch_size': 500,
    'max_workers': 6,  # Default to 6 as per your workflow
    'cache_ttl': 86400 * 7,
    'dns_servers': {
        'domestic': ['223.5.5.5', '119.29.29.29', '114.114.114.114'],
        'overseas': ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    },
    'whitelist': {
        'baidu.com', 'qq.com', 'taobao.com'
    }
}

class DNSValidator:
    def __init__(self, config):
        self.config = config
        self.tld_extract = tldextract.TLDExtract(cache_dir='/tmp/tldcache')
        self._init_cache()
        self.stats = {'total': 0, 'cached': 0, 'checked': 0, 'removed': 0}
        self.last_progress_report = 0

    def _init_cache(self):
        """Initialize cache database"""
        with sqlite3.connect(self.config['cache_db']) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS domains (
                    domain TEXT PRIMARY KEY,
                    valid_domestic INTEGER,
                    valid_overseas INTEGER,
                    checked_at INTEGER,
                    expires_at INTEGER
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_domain ON domains(domain)')

    def _clean_cache(self):
        """Clean expired cache entries"""
        with sqlite3.connect(self.config['cache_db']) as conn:
            conn.execute('DELETE FROM domains WHERE expires_at < ?', (int(time.time()),))

    def _report_progress(self, force=False):
        """Report progress to avoid timeout"""
        now = time.time()
        if force or now - self.last_progress_report > 60:  # Report every minute
            print(f"⏳ Processed: {self.stats['total']} | "
                  f"Cached: {self.stats['cached']} | "
                  f"Checked: {self.stats['checked']}")
            self.last_progress_report = now

    def validate_domain(self, domain):
        """Validate a single domain"""
        if domain in self.config['whitelist']:
            return True

        # Check cache
        with sqlite3.connect(self.config['cache_db']) as conn:
            row = conn.execute(
                'SELECT valid_domestic, valid_overseas FROM domains WHERE domain=? AND expires_at>=?',
                (domain, int(time.time()))
            ).fetchone()

            if row:
                self.stats['cached'] += 1
                return any(row)

        # Actual DNS check
        self.stats['checked'] += 1
        domestic_ok = self._check_with_servers(domain, self.config['dns_servers']['domestic'])
        overseas_ok = self._check_with_servers(domain, self.config['dns_servers']['overseas'])

        # Update cache
        with sqlite3.connect(self.config['cache_db']) as conn:
            conn.execute(
                'INSERT OR REPLACE INTO domains VALUES (?, ?, ?, ?, ?)',
                (domain, int(domestic_ok), int(overseas_ok),
                int(time.time()), int(time.time()) + self.config['cache_ttl'])
            )

        self._report_progress()
        return domestic_ok or overseas_ok

    def _check_with_servers(self, domain, servers):
        """Check domain with multiple DNS servers"""
        with ThreadPoolExecutor(max_workers=min(3, self.config['max_workers'])) as executor:
            futures = [executor.submit(self._dig_query, domain, server) for server in servers]
            for future in as_completed(futures, timeout=self.config['timeout']*3):
                if future.result():
                    return True
        return False

    def _dig_query(self, domain, server):
        """Execute dig query with timeout"""
        try:
            cmd = ['dig', f'@{server}', domain, 'A', '+short', '+time=1', '+tries=1']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config['timeout'])
            return bool(result.stdout.strip())
        except:
            return False

    def _extract_domain(self, rule):
        """Extract clean domain from rule"""
        rule = re.sub(r'^\|\|', '', rule)
        rule = re.sub(r'\^.*$', '', rule)
        rule = re.sub(r'\$.*$', '', rule)
        return rule.split('/')[0].lower()

    def process_file(self, file):
        """Process a single rule file"""
        print(f"🔍 Processing {file.name}...")
        tmp_file = file.with_suffix('.tmp')

        with open(file, 'r', encoding='utf-8', errors='ignore') as fin:
            lines = fin.readlines()

        valid_lines = []
        batch = []

        for line in lines:
            line = line.strip()
            if not line or line[0] in ('!', '#', '@'):
                valid_lines.append(line)
                continue

            domain = self._extract_domain(line)
            if not re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', domain):
                valid_lines.append(line)
                continue

            self.stats['total'] += 1
            batch.append((line, domain))

            if len(batch) >= self.config['batch_size']:
                self._process_batch(batch, valid_lines)
                batch = []
                self._report_progress()

        if batch:
            self._process_batch(batch, valid_lines)

        with open(tmp_file, 'w', encoding='utf-8') as fout:
            fout.write('\n'.join(valid_lines) + '\n')

        tmp_file.replace(file)
        self._report_progress(force=True)

        removed = self.stats['total'] - len([l for l in valid_lines if l and l[0] not in ('!', '#', '@')])
        print(f"✅ Finished {file.name}")
        print(f"   Total rules: {self.stats['total']} | Removed: {removed}")
        print(f"   Cache hits: {self.stats['cached']} | Fresh checks: {self.stats['checked']}")

    def _process_batch(self, batch, valid_lines):
        """Process a batch of domains"""
        domains = [item[1] for item in batch]
        with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            results = list(executor.map(self.validate_domain, domains))

        for (line, _), is_valid in zip(batch, results):
            if is_valid:
                valid_lines.append(line)

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='DNS Validation Tool')
    parser.add_argument('--input-dir', type=str, default='tmp', help='Input directory')
    parser.add_argument('--timeout', type=int, default=2, help='DNS query timeout')
    parser.add_argument('--workers', type=int, default=6, help='Max worker threads')
    parser.add_argument('--cache-file', type=str, default='tmp/dns_cache.db', help='Cache database file')
    parser.add_argument('--batch-size', type=int, default=500, help='Batch processing size')
    return parser.parse_args()

def main():
    args = parse_args()
    
    config = DEFAULT_CONFIG.copy()
    config.update({
        'input_dir': Path(args.input_dir),
        'timeout': args.timeout,
        'max_workers': args.workers,
        'cache_db': Path(args.cache_file),
        'batch_size': args.batch_size
    })

    validator = DNSValidator(config)
    validator._clean_cache()

    for file in config['input_dir'].glob('*.txt'):
        validator.process_file(file)
        validator.stats = {'total': 0, 'cached': 0, 'checked': 0, 'removed': 0}

if __name__ == '__main__':
    main()