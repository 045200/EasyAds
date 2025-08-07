from pathlib import Path
import re

def is_valid_rule(line: str) -> bool:
    """宽松的规则验证逻辑"""
    line = line.strip()
    if not line:
        return False
    if line.startswith(("#", "!", "//")):  # 跳过注释行
        return False
    if line.count("#") > 1:  # 跳过CSS规则
        return False
    return True

def normalize_rule(rule: str) -> str:
    """标准化规则格式（保留原始大小写）"""
    rule = rule.strip()
    # 处理AdGuard语法
    if rule.startswith("||") and rule.endswith("^"):
        return rule[2:-1]  # 移除通配符标记
    if rule.startswith("@@"):
        return rule[2:]  # 提取白名单域名
    return rule

def process_rules():
    # 兼容GitHub Actions路径
    base_dir = Path(__file__).parent
    tmp_dir = base_dir / "tmp"
    output_dir = base_dir / "data" / "rules"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. 优先加载白名单（宽松模式）
    allow_rules = set()
    for file in sorted(tmp_dir.glob("allow*.txt")):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if is_valid_rule(line):
                        rule = normalize_rule(line)
                        if rule:  # 空规则检查
                            allow_rules.add(rule)
        except Exception as e:
            print(f"⚠️ 跳过损坏文件 {file.name}: {str(e)}")

    # 2. 处理黑名单（保留非白名单规则）
    final_rules = set()
    for file in sorted(tmp_dir.glob("adblock*.txt")):
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if is_valid_rule(line):
                        rule = normalize_rule(line)
                        if rule and rule not in allow_rules:
                            final_rules.add(rule)
        except Exception as e:
            print(f"⚠️ 跳过损坏文件 {file.name}: {str(e)}")

    # 3. 写入最终文件（保留原始格式）
    with open(output_dir / "adblock.txt", "w", encoding="utf-8") as f:
        f.write("! 最终拦截规则（已过滤白名单冲突）\n")
        f.writelines(line + "\n" for line in sorted(final_rules))

    with open(output_dir / "allow.txt", "w", encoding="utf-8") as f:
        f.write("! 最终白名单规则\n")
        f.writelines("@@" + line + "\n" for line in sorted(allow_rules))

    print(f"✅ 处理完成！生成 {len(final_rules)}条拦截规则 + {len(allow_rules)}条白名单规则")

if __name__ == "__main__":
    process_rules()