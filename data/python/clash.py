import re
from datetime import datetime
from typing import List
# 处理时区（确保获取北京时间）
try:
    from zoneinfo import ZoneInfo
    beijing_tz = ZoneInfo("Asia/Shanghai")
except ImportError:
    import pytz
    beijing_tz = pytz.timezone("Asia/Shanghai")


def convert_adguard_rule(adguard_rule: str) -> str:
    """将单条AdGuard Home规则转换为Clash/Mihomo规则"""
    # 处理注释（直接转换为YAML注释）
    if adguard_rule.strip().startswith('!'):
        return f"# {adguard_rule.strip()[1:].strip()}"

    # 忽略空行
    if not adguard_rule.strip():
        return ""

    # 忽略AdGuard元信息行（如[Adblock Plus 2.0]）
    if adguard_rule.strip().startswith('[') and adguard_rule.strip().endswith(']'):
        return ""

    original_rule = adguard_rule.strip()
    rule = original_rule
    is_whitelist = False  # 是否为白名单规则

    # 处理白名单规则（@@前缀）
    if rule.startswith('@@'):
        is_whitelist = True
        rule = rule[2:]

    # 处理通配符规则（||前缀）
    if rule.startswith('||'):
        domain = re.sub(r'^\|\|(.*?)\^?$', r'\1', rule).split('$')[0].strip()
        action = "DIRECT" if is_whitelist else "REJECT"
        return f"DOMAIN-SUFFIX,{domain},{action}"

    # 处理子域名通配符（*.ad.com）
    if rule.startswith('*.'):
        domain = rule[2:].split('$')[0].strip()
        action = "DIRECT" if is_whitelist else "REJECT"
        return f"DOMAIN-SUFFIX,{domain},{action}"

    # 处理正则规则（/regex/格式）
    if rule.startswith('/') and rule.endswith('/') and len(rule) >= 2:
        regex = rule[1:-1]
        if len(regex) < 3:
            return ""
        action = "DIRECT" if is_whitelist else "REJECT"
        return f"URL-REGEX,{regex},{action}"

    # 处理普通域名（如example.com）
    if re.match(r'^[a-zA-Z0-9\-\.]+$', rule.split('$')[0].strip()):
        domain = rule.split('$')[0].strip()
        action = "DIRECT" if is_whitelist else "REJECT"
        if '.' in domain:
            return f"DOMAIN-SUFFIX,{domain},{action}"
        else:
            return f"DOMAIN,{domain},{action}"

    # 未匹配到的规则返回空
    return ""


def generate_ads_yaml(
    input_file: str = "../../dns.txt",  # 脚本位于/data/python/，根目录为上两级
    output_file: str = "../../ads.yaml"  # 输出到根目录
) -> None:
    """从根目录的dns.txt生成根目录的ads.yaml（脚本位于/data/python/）"""
    # 读取根目录的输入文件
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            adguard_rules = f.readlines()
    except FileNotFoundError:
        print(f"错误：未在根目录找到输入文件 {input_file}")
        return

    # 转换所有规则（过滤空行）
    converted_rules: List[str] = []
    for line in adguard_rules:
        converted = convert_adguard_rule(line)
        if converted.strip():
            converted_rules.append(converted)

    # 去重并排序
    unique_rules = sorted(list(set(converted_rules)))

    # 获取当前北京时间
    beijing_time = datetime.now(beijing_tz)
    time_str = beijing_time.strftime('%Y-%m-%d %H:%M:%S')

    # 构建YAML内容
    yaml_content = [
        "# Title: AdGuard 转换的广告过滤规则集",
        f"# Update time: {time_str} 北京时间",
        "# Source: https://github.045200/EasyAds",
        "# Script location: 每12小时更新一次，有问题提交lssues",
        "# Compatible: Clash / Mihomo",
        "",
        "payload:"
    ]

    # 添加转换后的规则
    yaml_content.extend([f"  - {rule}" if not rule.startswith('#') else rule for rule in unique_rules])

    # 写入根目录的输出文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(yaml_content))
        print(f"转换完成！根目录生成规则文件：{output_file}，共 {len(unique_rules)} 条有效规则")
    except Exception as e:
        print(f"写入文件失败：{e}")


if __name__ == "__main__":
    generate_ads_yaml()
