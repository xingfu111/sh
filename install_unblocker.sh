#!/bin/bash
install_path="/opt/apple_auto"

echo "以全新方式管理你的自动化Apple ID&解锁Apple ID问题程序"
echo "项目地址：github.com/pplulee/appleid_auto"
echo "项目交流TG群：@appleunblocker"
echo "使用时请确保本机已安装 Python3.6+ pip3 Docker"
echo "================================================= ================"
如果 python3 -V >/dev/null 2>&1; 然后
    echo "Python3 已安装"
    python_path=$(哪个python3)
    echo "Python3路径：$python_path"
别的
    echo "Python3未安装，开始安装……"
    如果 [ -f /etc/debian_version ]; 然后
        apt update && apt -y install python3 python3-pip
    elif [ -f /etc/redhat-release ]; 然后
        yum -y 安装 python3 python3-pip
    别的
       echo "无法检测到当前系统，已退出"
       出口;
    菲
菲
如果 pip3 >/dev/null 2>&1; 然后
    echo "pip3 已安装"
别的
    echo "pip3未安装，开始安装……"
    如果 [ -f /etc/debian_version ]; 然后
        apt update && apt -y 安装 python3-pip
    elif [ -f /etc/redhat-release ]; 然后
        yum -y 安装 python3-pip
    别的
       echo "无法检测到当前系统，已退出"
       出口;
    菲
    echo "pip3安装完成"
菲
如果 docker >/dev/null 2>&1; 然后
    echo "Docker 已安装"
别的
    echo "Docker未安装，开始安装……"
    码头工人版本 > /dev/null || curl -fsSL get.docker.com | 重击
    systemctl enable docker && systemctl restart docker
    echo "Docker 安装完成"
菲
echo "开始Apple_Auto安装"
echo "请输入API URL（http://xxx.xxx）"
读取 -e api_url
echo "请输入 API 密钥"
读取 -e api_key
mkdir install_unblocker
cd install_unblocker
echo "开始下载文件……"
wget https://raw.githubusercontent.com/pplulee/appleid_auto/main/backend/requirements.txt -O requirements.txt
wget https://raw.githubusercontent.com/pplulee/appleid_auto/main/backend/unblocker_manager.py -O unblocker_manager.py
SERVICE_FILE="[单位]
说明=appleauto
想要=network.target
[服务]
工作目录=$install_path
ExecStart=$python_path $install_path/unblocker_manager.py -api_url $api_url -api_key $api_key
重启=on-异常
重启秒=5s
KillMode=混合
[安装]
WantedBy=多用户.target"
如果 [ ！-f "unblocker_manager.py" ];然后
    echo "主程序文件不存在，请检查"
    1号出口
菲
如果 [ ！-d "$install_path" ]; 然后
    mkdir "$install_path"
菲
pip3 install -r requirements.txt
cp unblocker_manager.py "$install_path"/unblocker_manager.py
如果 [ ！-f "/usr/lib/systemd/system/appleauto.service" ];然后
    rm -rf /usr/lib/systemd/system/appleauto.service
菲
echo -e "${SERVICE_FILE}" > /lib/systemd/system/appleauto.service
systemctl 守护进程重载
systemctl 启用 appleauto
systemctl 重启 appleauto
systemctl 状态 appleauto
echo "默认服务名：appleauto"
echo "安装完成"
出口 0
