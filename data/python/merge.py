from pathlib import Path
import re

def normalize_rule(rule: str) -> str:
    """标准化规则格式（保持大小写敏感）"""
    rule = rule.strip()
    # 处理特殊规则语法
    if rule.startswith("||") and rule.endswith("^"):
        return rule[2:-1]  # 移除通配符标记
    return rule

def process_rules():
    # 路径设置
    base_dir = Path(__file__).parent
    tmp_dir = base_dir / "tmp"
    output_dir = base_dir / "data" / "rules"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. 优先处理白名单
    print("🔄 处理白名单规则...")
    allow_rules = set()
    for file in sorted(tmp_dir.glob("allow*.txt")):
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = normalize_rule(line)
                if line and not line.startswith(("#", "!", "//")) and "##" not in line:
                    if line.startswith("@@"):
                        allow_rules.add(line[2:])  # 提取白名单域名
                    else:
                        allow_rules.add(line)

    # 2. 处理黑名单并过滤冲突规则
    print("🔄 处理拦截规则...")
    final_rules = set()
    for file in sorted(tmp_dir.glob("adblock*.txt")):
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = normalize_rule(line)
                if line and not line.startswith(("#", "!", "@@", "//")) and "##" not in line:
                    if line not in allow_rules:  # 关键过滤逻辑
                        final_rules.add(line)

    # 3. 写入最终文件
    print("💾 生成最终规则文件...")
    with open(output_dir / "adblock.txt", "w", encoding="utf-8") as f:
        f.write("! 由AdGuard规则处理器生成\n")
        f.write("! 白名单优先处理，已自动过滤冲突规则\n")
        f.writelines(sorted(rule + "\n" for rule in final_rules))

    with open(output_dir / "allow.txt", "w", encoding="utf-8") as f:
        f.write("! 白名单规则（优先级最高）\n")
        f.writelines(sorted("@@" + rule + "\n" for rule in allow_rules))

    print(f"✅ 处理完成！生成 {len(final_rules)}条拦截规则 + {len(allow_rules)}条白名单规则")

if __name__ == "__main__":
    process_rules()