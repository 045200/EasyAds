import os
import subprocess
import time
import shutil

# 删除目录下所有的文件
directory = "./data/rules/"

# 确保目录存在并遍历删除其中的文件
if os.path.exists(directory):
    for file_name in os.listdir(directory):
        file_path = os.path.join(directory, file_name)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f"无法删除文件: {file_path}, 错误: {e}")
else:
    print(f"目录 {directory} 不存在")

# 删除目录本身
try:
    shutil.rmtree(directory)
    print(f"成功删除目录 {directory} 及其中的所有文件")
except Exception as e:
    print(f"无法删除目录 {directory}, 错误: {e}")

# 创建临时文件夹
os.makedirs("./tmp/", exist_ok=True)

# 复制补充规则到tmp文件夹
subprocess.run("cp ./data/mod/adblock.txt ./tmp/adblock01.txt", shell=True)
subprocess.run("cp ./data/mod/whitelist.txt ./tmp/allow01.txt", shell=True)


# 拦截规则
adblock = [
     "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt",
  "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
  "https://raw.githubusercontent.com/Cats-Team/dns-filter/main/abp.txt",

"https://raw.hellogithub.com/hosts",
 "https://raw.githubusercontent.com/qq5460168/dangchu/main/adhosts.txt",
    "https://lingeringsound.github.io/10007_auto/adb.txt",

"https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Replenish.txt",

"https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt",
  "https://github.com/entr0pia/fcm-hosts/raw/fcm/fcm-hosts",
  "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/refs/heads/main/black.txt",
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
  "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/refs/heads/master/SMAdHosts",
 "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingBlockList.txt",
  "https://raw.githubusercontent.com/twoone-3/AdGuardHomeForRoot/refs/heads/main/src/bin/data/filters/1732747955.txt"
]

# 白名单规则
allow = [

"https://raw.githubusercontent.com/qq5460168/dangchu/main/white.txt",
  "https://raw.githubusercontent.com/mphin/AdGuardHomeRules/main/Allowlist.txt",
  "https://file-git.trli.club/file-hosts/allow/Domains",
  "https://raw.githubusercontent.com/jhsvip/ADRuls/main/white.txt",
  "https://raw.githubusercontent.com/liwenjie119/adg-rules/master/white.txt",
  "https://raw.githubusercontent.com/miaoermua/AdguardFilter/main/whitelist.txt",
  "https://raw.githubusercontent.com/Kuroba-Sayuki/FuLing-AdRules/refs/heads/main/FuLingRules/FuLingAllowList.txt",
  "https://raw.githubusercontent.com/urkbio/adguardhomefilter/main/whitelist.txt",

"https://anti-ad.net/easylist.txt"
]

# 下载
for i, adblock_url in enumerate(adblock):
    subprocess.Popen(f"curl -m 60 --retry-delay 2 --retry 5 -k -L -C - -o tmp/adblock{i}.txt --connect-timeout 60 -s {adblock_url} | iconv -t utf-8", shell=True).wait()
    time.sleep(1)

for j, allow_url in enumerate(allow):
    subprocess.Popen(f"curl -m 60 --retry-delay 2 --retry 5 -k -L -C - -o tmp/allow{j}.txt --connect-timeout 60 -s {allow_url} | iconv -t utf-8", shell=True).wait()
    time.sleep(1)
    
print('规则下载完成')


