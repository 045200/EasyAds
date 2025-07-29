import subprocess
import datetime
import pytz
from pathlib import Path
import json
import re
import sys

def generate_release_template():
    try:
        # 定义文件路径（修正可能的拼写错误）
        rule_files = {
            'adblock': Path('./data/rules/adblock.txt'),
            'dns': Path('./data/rules/dns.txt'),
            'allow': Path('./data/rules/allow.txt')
        }
        
        # 验证文件存在
        for name, path in rule_files.items():
            if not path.exists():
                raise FileNotFoundError(f"{path} not found")
            print(f"Found {name} rules at: {path}")

        # 提取规则计数（更健壮的正则匹配）
        counts = {}
        for name, path in rule_files.items():
            try:
                # 方法1：尝试用sed提取
                result = subprocess.run(
                    ["sed", "-n", r"/^! Total count: \([0-9]\+\)/ {s//\1/p;q}", str(path)],
                    capture_output=True, text=True
                )
                count = result.stdout.strip()
                
                # 方法2：如果sed失败，改用Python直接读取
                if not count.isdigit():
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        match = re.search(r'^! Total count: (\d+)', content, re.MULTILINE)
                        if match:
                            count = match.group(1)
                
                if not count or not count.isdigit():
                    raise ValueError(f"无法从 {path} 中提取有效计数")
                
                counts[name] = count
                print(f"{name} 规则计数: {count}")
                
            except Exception as e:
                print(f"处理 {path} 时出错: {str(e)}", file=sys.stderr)
                raise
        
        # 获取北京时间
        beijing_time = datetime.datetime.now(pytz.timezone('Asia/Shanghai'))
        date_str = beijing_time.strftime('%Y-%m-%d')
        time_str = beijing_time.strftime('%H:%M:%S')
        tag_name = f"release-{beijing_time.strftime('%Y%m%d-%H%M')}"
        
        # 生成发布模板
        release_template = {
            "tag_name": tag_name,
            "name": f"规则更新 {date_str}",
            "body": f"""## 规则更新 {date_str}

**更新时间**: {date_str} {time_str} (北京时间)

### 规则统计
- 拦截规则数量: {counts['adblock']}
- DNS拦截规则数量: {counts['dns']}
- 白名单规则数量: {counts['allow']}

### 更新说明
本次更新包含以下变化:
1. 常规规则更新
2. 有问题请提交 Issues 反馈
3. 欢迎订阅: https://t.me/adbye66
4. 或者加入: https://t.me/adbye99""",
            "draft": False,
            "prerelease": False
        }
        
        # 将模板写入文件
        output_file = Path('release_template.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(release_template, f, ensure_ascii=False, indent=2)
        
        print(f"成功生成发布模板: {output_file}")
        print(json.dumps(release_template, indent=2, ensure_ascii=False))
        return True
        
    except Exception as e:
        print(f"生成发布模板失败: {str(e)}", file=sys.stderr)
        # 创建空的JSON文件防止后续步骤失败
        Path('release_template.json').write_text('{}', encoding='utf-8')
        return False

if __name__ == "__main__":
    sys.exit(0 if generate_release_template() else 1)