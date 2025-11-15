import signal
import logging
import coloredlogs
import os
import asyncio


from init import init
from init import tunnel
from init import route

import run
import config



debug = os.environ.get("DEBUG", False)

coloredlogs.install(level=logging.INFO)
logging.getLogger('wintun').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('quic').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('asyncio').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('zeroconf').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('parso.cache').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('parso.cache.pickle').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('parso.python.diff').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('humanfriendly.prompts').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('blib2to3.pgen2.driver').setLevel(logging.DEBUG if debug else logging.WARNING)
logging.getLogger('urllib3.connectionpool').setLevel(logging.DEBUG if debug else logging.WARNING)


    # ===== 配速：首次交互 + 记住上次 =====
def ask_pace(default_pace_str):
    while True:
        pace_str = input(f"请输入配速（分钟秒钟，如 530 表示 5′30″/km）"
                         f" [直接回车={default_pace_str}]: ").strip()
        if not pace_str:                       # 回车
             pace_str = default_pace_str
        if len(pace_str) < 3:
                print("格式错误，重试！")
                continue
        try:
                minutes = int(pace_str[:-2])
                seconds = int(pace_str[-2:])
                if not (0 <= seconds < 60):
                    raise ValueError
                total_min = minutes + seconds / 60
                if total_min <= 0:
                    raise ValueError
                v = 1000 / (total_min * 60)
                print(f"→ 已设置 {minutes}′{seconds:02d}″/km ≈ {v:.2f} m/s")
                return v, pace_str          # 返回速度 + 字符串（留给下次当默认值）
        except ValueError:
              print("输入无效，示例：530")
        # ==========================
        
async def main():
    logger = logging.getLogger(__name__)
    coloredlogs.install(level=logging.INFO)
    logger.setLevel(logging.INFO)
    if debug:
        logger.setLevel(logging.DEBUG)
        coloredlogs.install(level=logging.DEBUG)

    init.init()
    logger.info("init done")
    # ===== 新增：交互选路线 =====
    route.choose_route_file()          # 把用户选择写进 config.config.routeConfig
    # ===========================

    config.config.v, new_pace = ask_pace(config.config.pace_default)     # 来自上次运行的默认值
    config.config.save_pace_default(new_pace)  #存储本次使用的配速

    logger.info("trying to start tunnel")
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    process, address, port = tunnel.tunnel()
    signal.signal(signal.SIGINT, original_sigint_handler)
    try:
        logger.debug(f"tunnel address: {address}, port: {port}")

        loc = route.get_route()
        logger.info(f"got route from {config.config.routeConfig}")

        try:
            print(f"已开始模拟跑步，速度大约为 {config.config.v} m/s")
            print("会无限循环，按 Ctrl+C 退出")
            print("请勿直接关闭窗口，否则无法还原正常定位")
            await run.run(address, port, loc, config.config.v)
        except KeyboardInterrupt:
            logger.debug("get KeyboardInterrupt (inner)")
            logger.debug(f"Is process alive? {process.is_alive()}")
        finally:
            logger.debug(f"Is process alive? {process.is_alive()}")
            logger.debug("Start to clear location")

    except KeyboardInterrupt:
        logger.debug("get KeyboardInterrupt (outer)")
    finally:
        logger.debug(f"Is process alive? {process.is_alive()}")
        logger.debug("terminating tunnel process")
        process.terminate()
        logger.info("tunnel process terminated")
        print("Bye")
    

    
if __name__ == "__main__":
    asyncio.run(main())