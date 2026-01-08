from abc import ABC


class SystemDependency(ABC):
    def __update_system_dependency(self):
        pass


class SystemManager(object):
    number_of_cores = 0
    kernel_cache_slide: hex = hex(0)
    kernel_slide: hex = hex(0)

    @staticmethod
    def kernel_cache_based_address(address: int) -> hex:
        return hex(address - int(SystemManager.kernel_cache_slide, 16))
