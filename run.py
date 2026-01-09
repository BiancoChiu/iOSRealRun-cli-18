"""
run.py
automatically run the route
"""

"""修正坐标误差，百度取点使用 BD-09 坐标系，iOS使用 WGS-09 坐标系，进行转换"""
import math
import time
import random
import asyncio
from main import loop_cnt
from util.speed import current_speed


from functools import lru_cache

from geopy.distance import geodesic

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation
from pymobiledevice3.services.dvt.dvt_secure_socket_proxy import DvtSecureSocketProxyService

def bd09Towgs84(position):
    wgs_p = {}

    x_pi = 3.14159265358979324 * 3000.0 / 180.0
    pi = 3.141592653589793238462643383  # π
    a = 6378245.0  # 长半轴
    ee = 0.00669342162296594323  # 偏心率平方

    def transform_lat(x, y):
        ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * math.sqrt(abs(x))
        ret += (20.0 * math.sin(6.0 * x * pi) + 20.0 * math.sin(2.0 * x * pi)) * 2.0 / 3.0
        ret += (20.0 * math.sin(y * pi) + 40.0 * math.sin(y / 3.0 * pi)) * 2.0 / 3.0
        ret += (160.0 * math.sin(y / 12.0 * pi) + 320 * math.sin(y * pi / 30.0)) * 2.0 / 3.0
        return ret

    def transform_lon(x, y):
        ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * math.sqrt(abs(x))
        ret += (20.0 * math.sin(6.0 * x * pi) + 20.0 * math.sin(2.0 * x * pi)) * 2.0 / 3.0
        ret += (20.0 * math.sin(x * pi) + 40.0 * math.sin(x / 3.0 * pi)) * 2.0 / 3.0
        ret += (150.0 * math.sin(x / 12.0 * pi) + 300.0 * math.sin(x / 30.0 * pi)) * 2.0 / 3.0
        return ret

    x = position['lng'] - 0.0065
    y = position['lat'] - 0.006
    z = math.sqrt(x * x + y * y) - 0.00002 * math.sin(y * x_pi)
    theta = math.atan2(y, x) - 0.000003 * math.cos(x * x_pi)

    gcj_lng = z * math.cos(theta)
    gcj_lat = z * math.sin(theta)

    d_lat = transform_lat(gcj_lng - 105.0, gcj_lat - 35.0)
    d_lng = transform_lon(gcj_lng - 105.0, gcj_lat - 35.0)

    rad_lat = gcj_lat / 180.0 * pi
    magic = math.sin(rad_lat)
    magic = 1 - ee * magic * magic
    sqrt_magic = math.sqrt(magic)

    d_lng = (d_lng * 180.0) / (a / sqrt_magic * math.cos(rad_lat) * pi)
    d_lat = (d_lat * 180.0) / (a * (1 - ee) / (magic * sqrt_magic) * pi)

    wgs_p["lat"] = gcj_lat * 2 - gcj_lat - d_lat
    wgs_p["lng"] = gcj_lng * 2 - gcj_lng - d_lng
    return wgs_p

@lru_cache(maxsize=1000)
def bd09Towgs84_cached(lng, lat):
    """缓存版本的坐标转换"""
    position = {'lng': lng, 'lat': lat}
    return bd09Towgs84(position)

# get the ditance according to the latitude and longitude
def geodistance(p1, p2):
    return geodesic((p1["lat"],p1["lng"]),(p2["lat"],p2["lng"])).m

def smooth(start, end, i):
    import math
    i = (i-start)/(end-start)*math.pi
    return math.sin(i)**2

def randLoc(loc: list, d=0.000025, n=5):
    import random
    import time
    import math
    # deepcopy loc
    result = []
    for i in loc:
        result.append(i.copy())

    center = {"lat": 0, "lng": 0}
    for i in result:
        center["lat"] += i["lat"]
        center["lng"] += i["lng"]
    center["lat"] /= len(result)
    center["lng"] /= len(result)

    # 预计算单位向量
    vectors = []
    for p in result:
        vec_lat = p["lat"] - center["lat"]
        vec_lng = p["lng"] - center["lng"]
        distance = math.sqrt(vec_lat**2 + vec_lng**2)
        if distance == 0:
            vectors.append({"lat": 0, "lng": 0})
        else:
            vectors.append({"lat": vec_lat / distance, "lng": vec_lng / distance})

    random.seed(time.time())
    for i in range(n):
        start = int(i*len(result)/n)
        end = int((i+1)*len(result)/n)
        offset = (2*random.random()-1) * d
        for j in range(start, end):
            smoothed_offset = offset * smooth(start, end, j)
            result[j]["lat"] += vectors[j]["lat"] * smoothed_offset
            result[j]["lng"] += vectors[j]["lng"] * smoothed_offset

    start = int((n-1)*len(result)/n) # 确保从正确的起点开始
    end = len(result)
    offset = (2*random.random()-1) * d
    for j in range(start, end):
        smoothed_offset = offset * smooth(start, end, j)
        result[j]["lat"] += vectors[j]["lat"] * smoothed_offset
        result[j]["lng"] += vectors[j]["lng"] * smoothed_offset
        
    return result

def fixLockT(loc: list, v, dt):
    fixedLoc = []
    
    for i in range(len(loc)):
        a = loc[i]
        b = loc[(i+1) % len(loc)]
        
        distance = geodistance(a, b)
        steps = max(1, int(distance / (v * dt)))
        
        # 预计算增量
        lat_step = (b["lat"] - a["lat"]) / steps
        lng_step = (b["lng"] - a["lng"]) / steps
        
        for j in range(steps):
            fixedLoc.append({
                "lat": a["lat"] + j * lat_step,
                "lng": a["lng"] + j * lng_step
            })
    
    return fixedLoc

async def run1(dvt, loc: list, v, dt=0.2):
    fixedLoc = fixLockT(loc, v, dt)
    nList = (5, 6, 7, 8, 9)
    n = nList[random.randint(0, len(nList)-1)]
    fixedLoc = randLoc(fixedLoc, n=n)  # a path will be divided into n parts for random route
    location_sim = LocationSimulation(dvt)
    clock = time.time()
    
    for i in fixedLoc:
        # 使用缓存的转换（需要将坐标转为可哈希的元组）
        converted = bd09Towgs84_cached(round(i['lng'], 8), round(i['lat'], 8))
        location_sim.set(*converted.values())
        elapsed = time.time() - clock
        if elapsed < dt:
            await asyncio.sleep(dt - elapsed)
        clock = time.time()

async def run(address, port, loc: list,d=15):
    global loop_cnt
    random.seed(time.time())
    rsd = RemoteServiceDiscoveryService((address, port))
    await asyncio.sleep(2)
    await rsd.connect()
    dvt = DvtSecureSocketProxyService(rsd)
    dvt.perform_handshake()
    while True:
        v = current_speed(loop_cnt)
        vRand = 1000/(1000/v-(2*random.random()-1)*d)
        print(f"当前速度为{vRand}/{v}")
        await run1(dvt, loc, vRand)
        print("跑完一圈了")
        loop_cnt += 1
