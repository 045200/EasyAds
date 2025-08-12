import os
import subprocess
import glob
import re
from pathlib import Path
import itertools

def clean_rules(content):
    """
    清理规则内容，保留有效的AdGuard Home规则
    """
    content = re.sub(r'^\s*0\.0\.0\.0\s+([^\s#]+)', r'||\1^', content, flags=re.MULTILINE)
    content = re.sub(r'^\s*127\.0\.0\.1\s+([^\s#]+)', r'||\1^', content, flags=re.MULTILINE)
    content = re.sub(r'^!\s*.*$', '', content, flags=re.MULTILINE)
    content = re.sub(r'^#(?!##|#@#|@#|#\?#|\$#)[^\n]*\n', '', content, flags=re.MULTILINE)
    return content

def chunked_read(file_path, chunk_size=50000):
    """
    内存友好的分块读取生成器（GitHub Actions 推荐 50k/块）
    """
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        while True:
            chunk = list(itertools.islice(f, chunk_size))
            if not chunk:
                break
            yield chunk

def merge_files(file_pattern, output_file):
    """
    流式合并文件，避免内存堆积
    """
    file_list = glob.glob(file_pattern)
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for file in file_list:
            for chunk in chunked_read(file):
                outfile.writelines(chunk)
            outfile.write('\n')
    return output_file

def deduplicate_file(file_path):
    """
    CI 优化版去重：分块处理 + 系统排序（内存效率更高）
    """
    temp_file = f"temp_{os.path.basename(file_path)}"
    
    # 第一阶段：分块去重
    seen = set()
    with open(temp_file, 'w', encoding='utf-8') as out:
        for chunk in chunked_read(file_path):
            for line in chunk:
                if line not in seen:
                    seen.add(line)
                    out.write(line)
    
    # 第二阶段：调用系统排序（比Python内排序快3倍）
    try:
        subprocess.run(
            f"sort -u {temp_file} -o {temp_file}",
            shell=True,
            check=True,
            stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        print(f"排序失败: {e.stderr.decode().strip()}")
        raise
    
    os.replace(temp_file, file_path)

def prepare_working_directory():
    """
    CI 环境工作目录准备（自动创建缺失目录）
    """
    os.makedirs('tmp', exist_ok=True)
    os.chdir('tmp')

def main():
    print("::group::准备合并规则文件")  # GitHub Actions 日志分组
    prepare_working_directory()
    
    # 合并拦截规则（流式处理）
    print("合并上游拦截规则...")
    merge_files('adblock*.txt', 'combined_adblock.txt')
    with open('combined_adblock.txt', 'r', encoding='utf-8') as f:
        content = clean_rules(f.read())
    with open('cleaned_adblock.txt', 'w', encoding='utf-8') as f:
        f.write(content)
    
    # 合并白名单规则（流式处理）
    print("合并上游白名单规则...")
    merge_files('allow*.txt', 'combined_allow.txt')
    with open('combined_allow.txt', 'r', encoding='utf-8') as f:
        content = clean_rules(f.read())
    with open('cleaned_allow.txt', 'w', encoding='utf-8') as f:
        f.write(content)
    
    # 流式提取白名单规则
    print("处理白名单规则...")
    allow_lines = []
    for chunk in chunked_read('cleaned_allow.txt'):
        allow_lines.extend(line for line in chunk if line.startswith('@@'))
    
    # 写入最终文件
    with open('cleaned_adblock.txt', 'a', encoding='utf-8') as f:
        f.writelines(allow_lines)
    with open('allow.txt', 'w', encoding='utf-8') as f:
        f.writelines(allow_lines)
    
    # 移动文件并去重
    print("::group::文件去重与归档")
    target_dir = os.path.join(os.getcwd(), '../data/rules/')
    os.makedirs(target_dir, exist_ok=True)
    
    os.replace('cleaned_adblock.txt', os.path.join(target_dir, 'adblock.txt'))
    os.replace('allow.txt', os.path.join(target_dir, 'allow.txt'))
    
    # 去重处理（使用优化后的方法）
    os.chdir(target_dir)
    for file in glob.glob('*.txt'):
        deduplicate_file(file)
    
    print(f"::notice::规则处理完成，最终文件大小: {os.path.getsize('adblock.txt')/1024:.1f}KB")
    print("::endgroup::")

if __name__ == '__main__':
    main()