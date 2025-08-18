import os
import concurrent.futures
import requests
import shutil
from glob import glob

def clean_files():
    """清理根目录下的.txt和.mrs文件"""
    try:
        # 获取根目录下所有.txt和.mrs文件
        files_to_delete = glob('./*.txt') + glob('./*.mrs')
        
        for file_path in files_to_delete:
            try:
                os.remove(file_path)
                print(f"已删除文件: {file_path}")
            except Exception as e:
                print(f"无法删除文件 {file_path}, 错误: {e}")
                
    except Exception as e:
        print(f"清理文件时发生错误: {e}")

def create_temp_dir():
    """创建临时目录并复制本地规则"""
    os.makedirs("./tmp/", exist_ok=True)
    # 复制本地规则到临时目录
    for src, dest in [("./data/mod/adblock.txt", "./tmp/adblock01.txt"),
                     ("./data/mod/whitelist.txt", "./tmp/allow01.txt")]:
        try:
            shutil.copy2(src, dest)
        except Exception as e:
            print(f"无法复制文件 {src} 到 {dest}, 错误: {e}")

def download_file(url, filename, timeout=30):
    """下载单个规则文件"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        with open(filename, 'wb') as f:
            f.write(response.content)
        return True
    except Exception as e:
        print(f"下载失败: {url}, 错误: {str(e)}")
        return False

def download_rules():
    """主下载函数"""
    # 规则源列表
    adblock = [
        "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
        "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
        "https://raw.hellogithub.com/hosts",
        #"https://raw.githubusercontent.com/Cats-Team/AdRules/main/adblock.txt",
        #"https://raw.githubusercontent.com/qq5460168/666/main/adblock.txt",
        #"https://lingeringsound.github.io/10007_auto/adb.txt",
        "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt",
        "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
        "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",
        "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts",
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingBlockList.txt"
    ]

    allow = [
        "https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
        "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
        "https://file-git.trli.club/file-hosts/allow/Domains",
        "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
        "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
        "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
        "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/main/FuLingRules/FuLingAllowList.txt",
        "https://raw.githubusercontent.com/Cats-Team/AdRules/script/script/allowlist.txt",
        "https://raw.githubusercontent.com/user001235/112/main/white.txt",
        "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",
        
"https://anti-ad.net/easylist.txt"
    ]

    # 使用线程池并发下载
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # 下载拦截规则
        futures = []
        for i, url in enumerate(adblock, start=2):
            filename = f"./tmp/adblock{i:02d}.txt"
            futures.append(executor.submit(download_file, url, filename))
        
        # 下载白名单规则
        for j, url in enumerate(allow, start=2):
            filename = f"./tmp/allow{j:02d}.txt"
            futures.append(executor.submit(download_file, url, filename))
        
        # 等待所有下载完成
        concurrent.futures.wait(futures)

if __name__ == "__main__":
    clean_files()  # 清理根目录的.txt和.mrs文件
    create_temp_dir()
    download_rules()
    print('规则下载完成')