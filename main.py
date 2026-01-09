import asyncio
import logging
import os
import signal

import coloredlogs

import config
import run
from init import init, route, tunnel
from util import speed

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

loop_cnt = 0

async def main():
    global loop_cnt
    logger = logging.getLogger(__name__)
    coloredlogs.install(level=logging.INFO)
    logger.setLevel(logging.INFO)
    if debug:
        logger.setLevel(logging.DEBUG)
        coloredlogs.install(level=logging.DEBUG)

    init.init()
    logger.info("init done")

    logger.info("trying to start tunnel")
    original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    process, address, port = tunnel.tunnel()
    signal.signal(signal.SIGINT, original_sigint_handler)
    try:
        logger.debug(f"tunnel address: {address}, port: {port}")

        loc = route.get_route()
        logger.info(f"got route from {config.config.routeConfig}")

        try:
            print(f"已开始模拟跑步, 目前是第{loop_cnt +1}/{config.config.target_loops}圈")
            print("会无限循环，按 Ctrl+C 退出")
            print("请勿直接关闭窗口，否则无法还原正常定位")
            await run.run(address, port, loc)
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

    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
    
