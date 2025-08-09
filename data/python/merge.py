from pathlib import Path

def is_valid_rule(line: str) -> bool:
    """宽松的规则验证逻辑"""
    line = line.strip()
    if not line:
        return False
    if line.startswith(("#", "!", "//")):  # 跳过注释行
        return False
    return True

def normalize_rule(rule: str) -> str:
    """标准化规则格式（保留原始大小写）"""
    rule = rule.strip()
    if rule.startswith("||") and rule.endswith("^"):
        return rule[2:-1]
    if rule.startswith("@@"):
        return rule[2:]
    return rule

def process_rules():
    # 设置路径
    tmp_dir = Path("/home/runner/work/EasyAds/EasyAds/tmp")
    output_dir = tmp_dir.parent / "data" / "rules"
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. 加载白名单
    allow_rules = set()
    for file in sorted(tmp_dir.glob("allow*.txt")):
        if file.stat().st_size == 0:
            print(f"⚠️ 空文件跳过: {file.name}")
            continue
        try:
            print(f"📄 正在处理白名单文件: {file.name}")
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                print(f"文件 {file.name} 总行数: {len(lines)}")
                for line in lines[:5]:  # 打印前5行内容
                    print(f"预览: {line.strip()}")
                for line in lines:
                    if is_valid_rule(line):
                        rule = normalize_rule(line)
                        if rule:
                            allow_rules.add(rule)
            print(f"✅ 读取完成: {file.name}，白名单规则数量: {len(allow_rules)}")
        except Exception as e:
            print(f"⚠️ 跳过损坏文件 {file.name}: {str(e)}")

    # 2. 处理拦截规则
    final_rules = set()
    for file in sorted(tmp_dir.glob("adblock*.txt")):
        if file.stat().st_size == 0:
            print(f"⚠️ 空文件跳过: {file.name}")
            continue
        try:
            print(f"📄 正在处理拦截规则文件: {file.name}")
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                print(f"文件 {file.name} 总行数: {len(lines)}")
                for line in lines[:5]:  # 打印前5行内容
                    print(f"预览: {line.strip()}")
                for line in lines:
                    if is_valid_rule(line):
                        rule = normalize_rule(line)
                        if rule and rule not in allow_rules:
                            final_rules.add(rule)
            print(f"✅ 读取完成: {file.name}，当前拦截规则数量: {len(final_rules)}")
        except Exception as e:
            print(f"⚠️ 跳过损坏文件 {file.name}: {str(e)}")

    # 3. 检查冲突
    conflict_count = sum(1 for rule in final_rules if rule in allow_rules)
    print(f"⚠️ 冲突规则数量: {conflict_count}")

    # 4. 写入最终文件
    try:
        with open(output_dir / "adblock.txt", "w", encoding="utf-8") as f:
            f.write("! 最终拦截规则（已过滤白名单冲突）\n")
            f.writelines(line + "\n" for line in sorted(final_rules))
        print(f"✅ 写入完成: {output_dir / 'adblock.txt'}")

        with open(output_dir / "allow.txt", "w", encoding="utf-8") as f:
            f.write("! 最终白名单规则\n")
            f.writelines("@@" + line + "\n" for line in sorted(allow_rules))
        print(f"✅ 写入完成: {output_dir / 'allow.txt'}")
    except Exception as e:
        print(f"✗ 写入最终文件失败: {str(e)}")

    print(f"✅ 处理完成！生成 {len(final_rules)} 条拦截规则 + {len(allow_rules)} 条白名单规则")

if __name__ == "__main__":
    process_rules()