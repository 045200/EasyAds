import re
from pathlib import Path

def merge_files(pattern, output_file):
    files = Path('tmp').glob(pattern)
    with open(output_file, 'w', encoding='utf8') as out:
        for file in files:
            with open(file, 'r', encoding='utf8') as f:
                out.write(f.read())
                out.write('\n')

def clean_rules(input_file, output_file):
    with open(input_file, 'r', encoding='utf8') as f:
        content = f.read()
    # 去除注释和无效行
    content = re.sub(r'^[!].*$\n', '', content, flags=re.MULTILINE)
    content = re.sub(r'^#(?!\s*#).*\n?', '', content, flags=re.MULTILINE)
    with open(output_file, 'w', encoding='utf8') as f:
        f.write(content)

def extract_allow_lines(allow_file, adblock_combined_file, allow_output_file):
    # 把 allow_file 的内容追加到 adblock_combined_file
    with open(allow_file, 'r', encoding='utf8') as f:
        allow_lines = f.readlines()
    with open(adblock_combined_file, 'a', encoding='utf8') as out:
        out.writelines(allow_lines)
    # 筛选出 adblock_combined_file 中以 @ 开头的行，写入 allow_output_file
    with open(adblock_combined_file, 'r', encoding='utf8') as f:
        lines = f.readlines()
    with open(allow_output_file, 'w', encoding='utf8') as f:
        for line in lines:
            if line.startswith('@'):
                f.write(line)

def move_files_to_target(adblock_file, allow_file, target_dir):
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    adblock_target = target_dir / 'adblock.txt'
    allow_target = target_dir / 'allow.txt'
    Path(adblock_file).rename(adblock_target)
    Path(allow_file).rename(allow_target)

def deduplicate_txt_files(target_dir):
    target_dir = Path(target_dir)
    for file in target_dir.glob('*.txt'):
        with open(file, 'r', encoding='utf8') as f(line)

def main():
    tmp_dir = Path('tmp')
    rules_dir = Path('data/rules')

    print("合并上游拦截规则")
    merge_files('adblock*.txt', tmp_dir / 'combined_adblock.txt')
    clean_rules(tmp_dir / 'combined_adblock.txt', tmp_dir / 'cleaned_adblock.txt')
    print("拦截规则合并完成")

    print("合并上游白名单规则")
    merge_files('allow*.txt', tmp_dir / 'combined_allow.txt')
    clean_rules(tmp_dir / 'combined_allow.txt', tmp_dir / 'cleaned_allow.txt')
    print("白名单规则合并完成")

    print("过滤白名单规则")
    extract_allow_lines(tmp_dir / 'cleaned_allow.txt', tmp_dir / 'combined_adblock.txt', tmp_dir / 'allow.txt')

    print("移动文件到目标目录")
    move_files_to_target(tmp_dir / 'cleaned_adblock.txt', tmp_dir / 'allow.txt', rules_dir)

    print("规则去重中")
    deduplicate_txt_files(rules_dir)
    print("规则去重完成")

if __name__ == '__main__':
    main()