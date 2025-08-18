import re
from pathlib import Path

def filter_adguard_home_rules(input_path, output_path):
    """
    专业处理AdGuard Home规则，提取有效DNS规则
    
    Args:
        input_path (str/Path): 输入规则文件路径
        output_path (str/Path): 输出DNS规则文件路径
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    # 完整AdGuard Home DNS规则正则
    DNS_RULE_PATTERN = re.compile(
        r'^(\|\|[\w.-]+\^($|[\w,=-]+)?)|'          # 基础域名规则
        r'^\|\|[\w.-]+\^\$dnstype=\w+|'           # DNS类型规则
        r'^\|\|[\w.-]+\^\$dnsrewrite=\w+|'        # DNS重写规则
        r'^@@\|\|[\w.-]+\^\$dnsrewrite=NOERROR|' # DNS重写例外
        r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$'        # Hosts格式
    )

    if not input_path.exists():
        raise FileNotFoundError(f"输入文件不存在: {input_path}")

    try:
        with input_path.open('r', encoding='utf-8') as infile, \
             output_path.open('w', encoding='utf-8') as outfile:

            count = 0
            seen = set()  # 用于去重
            
            for line in infile:
                line = line.strip()
                
                # 跳过注释和空行
                if not line or line.startswith(('!', '#')):
                    continue
                
                # 严格匹配DNS相关规则
                if DNS_RULE_PATTERN.match(line):
                    # 标准化规则格式
                    normalized = line.replace(' ', '')  # 移除hosts规则中的空格
                    if normalized.lower() not in seen:  # 不区分大小写去重
                        seen.add(normalized.lower())
                        outfile.write(normalized + '\n')
                        count += 1

            print(f"成功处理 {count} 条DNS规则，已保存到 {output_path}")

    except IOError as e:
        print(f"文件处理错误: {e}")
        raise

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent.parent
    input_file = base_dir / "adblock.txt"
    output_file = base_dir / "dns.txt"

    # 确保输出目录存在
    output_file.parent.mkdir(parents=True, exist_ok=True)

    filter_adguard_home_rules(input_file, output_file)