import yaml
import os

class Config:
    def __init__(self,yaml_path=None):
        yaml_path=yaml_path or os.path.join(os.path.dirname(__file__),'config.yaml')
        with open(yaml_path,encoding='utf-8') as f:
            y = yaml.safe_load(f) or {}
        for k,v in y.items:
            setattr(self, k, v)
        if not hasattr(self,'routeConfig'):
            self.routeConfig = None


config = Config()
