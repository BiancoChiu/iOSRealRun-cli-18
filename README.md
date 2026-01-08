# iOSRealRun-cli-18
---
[**@GH4NG**](https://github.com/GH4NG)基于Go开发了一款带有GUI的跑步软件，请大家尝试使用他的[仓库](https://github.com/GH4NG/iOSGhostRun)并测试提issue

本项目大概放弃继续更新了😋

---

本项目基于 [iOSRealRun-cli-17](https://github.com/iOSRealRun/iOSRealRun-cli-17) 修改而来，并更新了依赖的 [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)。

如果使用时出现了无法解决的报错可以考虑使用[这个仓库手动启动](https://github.com/BiancoChiu/iOSEasyRun)。

测试环境：
- 操作系统：MacOS，Windows11，Linux
- Python 版本：3.13
- iOS 版本：18.3.1

## 用法简介

### 前置条件

1. 系统是 `Windows`，`macOS`，`Linux` 均可（Linux 请参考[此 issue](https://github.com/BiancoChiu/iOSRealRun-cli-18/issues/4)）
2. iPhone 或 iPad 系统版本大于等于 17（17 / 18 / 26 均可运行）
3. Windows 需要安装 iTunes
4. 已安装 `Python3` 和 `uv` / `pip3` (选择一种方式即可）
5. **重要**: 只能有一台 iPhone 或 iPad 连接到电脑，否则会出问题

### 步骤

1. 克隆本项目到本地并进入项目目录
2. 安装依赖  
    ```shell
    # uv
    uv sync
    # pip
    pip3 install -r requirements.txt
    ```
3. 修改配置和路线文件 （见 [这里](https://github.com/iOSRealRun/iOSRealRun-cli/blob/main/README.md#%E4%BD%BF%E7%94%A8%E6%96%B9%E6%B3%95) 的 4、5、7 步）
4. 将设备连接到电脑，解锁，如果请求信任的提示框，请点击信任
5. Windows **以管理员身份** 打开终端（cmd 或 PowerShell），先进入项目目录，然后执行以下命令 
    ```shell
    # uv
    uv run main.py
    # pip
    python main.py
    ```
    macOS / Linux 打开终端，先进入项目目录，然后执行以下命令  
    ```shell
    # uv
    sudo uv run main.py
    # pip
    sudo python main.py
    ```
    > 需要 管理员 / root 权限是因为需要创建 TUN 设备  

6. 按照提示操作，如果一直显示没有设备连接，Windows 平台请确保 iTunes 已安装（可能需要打开），重新运行程序，在第 3 步时请确保设备已连接，解锁并信任
7. 结束请务必使用 `Ctrl + C` 终止程序，否则无法恢复定位
8. 如果定位未恢复，可以重启手机解决
