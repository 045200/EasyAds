import subprocess
import datetime
import pytz
from pathlib import Path
import json
import re

def generate_release_template():
    try:
        # 定义文件路径
        rule_files = {
            'adblock': Path('./data/rules/adblock.txt'),
            'dns': Path('./data/rules/dns.txt'),
            'allow': Path('./data/rules/allow.txt')
        }
        
        # 验证文件存在
        for name, path in rule_files.items():
            if not path.exists():
                raise FileNotFoundError(f"{path} not found")
        
        # 提取规则计数
        counts = {}
        for name, path in rule_files.items():
            result = subprocess.run(
                ["sed", "-n", r"s/^! Total count: //p", str(path)],
                capture_output=True, text=True, check=True
            )
            counts[name] = result.stdout.strip()
            if not counts[name].isdigit():
                raise ValueError(f"Invalid count in {path}")
        
        # 获取北京时间并生成合规标签
        beijing_time = (datetime.datetime.now(pytz.timezone('UTC'))
                        .astimezone(pytz.timezone('Asia/Shanghai')))
        date_str = beijing_time.strftime('%Y-%m-%d')
        time_str = beijing_time.strftime('%H:%M:%S')
        tag_name = f"release-{beijing_time.strftime('%Y%m%d-%H%M')}"  # 格式如 release-20250730-1836
        
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
        output_file = Path('./release_template.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(release_template, f, ensure_ascii=False, indent=2)
        
        print(f"已生成发布模板到 {output_file}")
        print("生成内容:")
        print(json.dumps(release_template, indent=2, ensure_ascii=False))
        return True
        
    except Exception as e:
        print(f"生成发布模板失败: {str(e)}")
        return False

if __name__ == "__main__":
    generate_release_template()