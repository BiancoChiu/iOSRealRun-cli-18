import yaml
import os

YAML_FILE = os.path.join(os.path.dirname(__file__), 'config.yaml')
class Config:
    def __init__(self,yaml_path=None):
        yaml_path=yaml_path or os.path.join(os.path.dirname(__file__),'config.yaml')
        with open(yaml_path,encoding='utf-8') as f:
            y = yaml.safe_load(f) or {}
        for k,v in y.items():
            setattr(self, k, v)
        if not hasattr(self,'routeConfig'):
            self.routeConfig = None
        if not hasattr(self, 'pace_default'):
            self.pace_default = '530'
    def save_pace_default(self, pace_str):
        with open(YAML_FILE, encoding='utf-8') as f:
            y = yaml.safe_load(f) or {}
        y['pace_default'] = pace_str
        with open(YAML_FILE, 'w', encoding='utf-8') as f:
            yaml.safe_dump(y, f, allow_unicode=True)

config = Config()
