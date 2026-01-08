from typing import Mapping, Any, List


class ThreadState:
    def __init__(self, index: int, state: str):
        self.__index = index
        self.__state = state


class Thread(object):
    def __init__(self, json_data: Mapping[str, Any]):
        self.__base_priority = json_data['basePriority']
        self.__schedule_priority = json_data['schedPriority']
        self.__id = json_data['id']
        self.__user_time = float(json_data['userTime'])
        self.__system_time = float(json_data['systemTime'])

        self.__state: List[ThreadState] = []
        states_raw: List[str] = json_data['state']
        for index, state in enumerate(states_raw):
            state = ThreadState(index, state)
            self.__state.append(state)

        self.__name = json_data.get('name')
        self.__kernel_frames = json_data.get('kernelFrames')
        self.__waitEvent = json_data.get('waitEvent')
        self.__continuation = json_data.get('continuation')
        self.__system_usec = json_data.get('system_usec')
        self.__user_usec = json_data.get('user_usec')


class Process(object):
    def __init__(self, json_data: Mapping[str, Any]):
        self.__pid = int(json_data['pid'])
        self.__resident_memory_bytes = int(json_data['residentMemoryBytes'])
        self.__times_did_throttled = json_data['timesDidThrottle']
        self.__system_time_task = int(json_data['systemTimeTask'])
        self.__page_ins = int(json_data['pageIns'])
        self.__page_faults = int(json_data['pageFaults'])
        self.__name = json_data['procname']
        self.__copy_on_write_faults = json_data['copyOnWriteFaults']
        self.__times_throttled = int(json_data['timesThrottled'])

        threads: List[Thread] = []
        threads_raw: Mapping[str, Mapping[str, Any]] = json_data['threadById']

        for thread_raw in threads_raw.values():
            threads.append(Thread(thread_raw))


class ProcessList(object):
    __processes: List[Process] = []

    def __init__(self, process_list_raw: Mapping[str, Any]):
        for process_raw in process_list_raw.values():
            self.__processes.append(Process(process_raw))
