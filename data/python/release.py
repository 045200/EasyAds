import subprocess
import datetime
import pytz
from pathlib import Path
import json

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
                ["sed", "-n", f"s/^! Total count: //p", str(path)],
                capture_output=True, text=True, check=True
            )
            counts[name] = result.stdout.strip()
            if not counts[name].isdigit():
                raise ValueError(f"Invalid count in {path}")
        
        # 获取北京时间
        beijing_time = (datetime.datetime.now(pytz.timezone('UTC'))
                        .astimezone(pytz.timezone('Asia/Shanghai'))
                        .strftime('%Y-%m-%d %H:%M:%S'))
        
        # 生成发布模板
        release_template = {
            "tag_name": f"v{beijing_time.split()[0]}",
            "name": f"规则更新 {beijing_time.split()[0]}",
            "body": f"""\
## 规则更新 {beijing_time.split()[0]}

**更新时间**: {beijing_time} (北京时间)

### 规则统计
- 拦截规则数量: {counts['adblock']}
- DNS拦截规则数量: {counts['dns']}
- 白名单规则数量: {counts['allow']}

### 更新说明
本次更新包含以下变化:
1. 常规规则更新
2. 有问题请提交lssues反馈
3. 欢迎订阅:https://t.me/adbye66
4. 或者加入:https://t.me/adbye99""",
            "draft": False,
            "prerelease": False
        }
        
        # 将模板写入文件，供后续步骤使用
        output_file = Path('./release_template.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(release_template, f, ensure_ascii=False, indent=2)
        
        print(f"已生成发布模板到 {output_file}")
        return True
        
    except Exception as e:
        print(f"生成发布模板失败: {str(e)}")
        return False

if __name__ == "__main__":
    generate_release_template()