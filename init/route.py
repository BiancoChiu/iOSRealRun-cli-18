import config
import os

from util import route

ROUTE_FILES = [
    'ZJGRoute_East.txt',
    'ZJGRoute_West.txt',
    'YQRoute.txt',
    'HNRoute.txt'
]
def choose_route_file():
    """让用户从预置路线里选"""
    print('===== 当前可用路线 =====')
    for idx, f in enumerate(ROUTE_FILES, 1):
        print(f'{idx}: {f}')
    while True:
        try:
            sel = int(input('请选择路线编号（输入数字后回车）: '))
            if 1 <= sel <= len(ROUTE_FILES):
                chosen = ROUTE_FILES[sel-1]
                if not os.path.isfile(chosen):
                    print(f'路线文件 {chosen} 不存在，请确认路径')
                    continue
                config.config.routeConfig = chosen
                print(f'已选择路线: {chosen}')
                return
        except ValueError:
            pass
        print('不合法的选择，请重试')


def get_route():
    with open(config.config.routeConfig,encoding='utf-8') as myFile:
        loc = route.parse_route(myFile.read())
    return loc  
