import os
import re
from pathlib import Path
from datetime import datetime
import pytz

def get_beijing_time():
    """获取北京时间 (UTC+8)"""
    tz = pytz.timezone('Asia/Shanghai')
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

def extract_to_loon_rules(input_file, output_file):
    """转换规则为Loon格式"""
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    try:
        with input_path.open('r', encoding='utf-8', errors='ignore') as infile:
            ip_rules, domain_rules, suffix_rules, keyword_rules = [], [], [], []
            ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?$')
            
            for line in infile:
                line = line.strip()
                if not line or line.startswith('!'):
                    continue
                
                if line.startswith("||") and line.endswith("^"):
                    rule = line[2:-1]
                    if ip_pattern.match(rule.split('/')[0]):
                        ip_rules.append(f"IP-CIDR,{rule},REJECT,no-resolve")
                    else:
                        suffix_rules.append(f"DOMAIN-SUFFIX,{rule},REJECT")
                elif line.startswith(("|http://", "|https://")):
                    domain = line.split('://')[1].split('^')[0].split('/')[0]
                    domain_rules.append(f"DOMAIN,{domain},REJECT")
                elif '*' in line:
                    keyword = line.replace('*', '').replace('^', '').replace('||', '')
                    if keyword:
                        keyword_rules.append(f"DOMAIN-KEYWORD,{keyword},REJECT")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        beijing_time = get_beijing_time()
        ip_count = len(set(ip_rules))
        domain_count = len(set(domain_rules))
        suffix_count = len(set(suffix_rules))
        keyword_count = len(set(keyword_rules))
        total_count = ip_count + domain_count + suffix_count + keyword_count

        with output_path.open('w', encoding='utf-8') as outfile:
            outfile.write("# Loon规则由GOODBYEADS生成\n")
            outfile.write(f"# 更新时间(北京时间): {beijing_time}\n")
            outfile.write(f"# 规则统计: 总计{total_count}条 (IP:{ip_count} DOMAIN:{domain_count} "
                         f"SUFFIX:{suffix_count} KEYWORD:{keyword_count})\n\n")
            
            if ip_rules:
                outfile.write("# IP规则\n" + "\n".join(sorted(set(ip_rules))) + "\n\n")
            if domain_rules:
                outfile.write("# 域名规则\n" + "\n".join(sorted(set(domain_rules))) + "\n\n")
            if suffix_rules:
                outfile.write("# 域名后缀\n" + "\n".join(sorted(set(suffix_rules))) + "\n\n")
            if keyword_rules:
                outfile.write("# 关键词规则\n" + "\n".join(sorted(set(keyword_rules))) + "\n")

        print(f"生成成功! 规则总数: {total_count}")

    except Exception as e:
        print(f"处理失败: {e}")
        raise

if __name__ == "__main__":
    script_dir = Path(__file__).parent
    input_file = script_dir.parent / "rules" / "dns.txt"
    output_file = script_dir.parent / "rules" / "loon-rules.list"
    extract_to_loon_rules(input_file, output_file)