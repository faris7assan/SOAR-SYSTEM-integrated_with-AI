"""
AegisNDR - Plugin System
Extensible detection plugin loader. Drop a .py file in /plugins/ to add detection.
"""
import os
import importlib.util
import logging
from typing import List, Dict, Any
from models import Flow, Alert

logger = logging.getLogger(__name__)

PLUGINS_DIR = os.path.join(os.path.dirname(__file__))


class PluginBase:
    """
    Base class all detection plugins must inherit.
    
    Example plugin:
    
        from plugins import PluginBase
        from models import Flow, Alert, AlertType, AlertSeverity
        
        class MyPlugin(PluginBase):
            name = "my_plugin"
            description = "Detects something custom"
            
            def analyze(self, flow: Flow) -> list[Alert]:
                if flow.dst_port == 1337:
                    return [self.make_alert(flow, AlertType.ANOMALY, 75, "Suspicious port 1337")]
                return []
    """
    name        = "base_plugin"
    description = "Base plugin — do not use directly"
    enabled     = True

    def analyze(self, flow: Flow) -> List[Alert]:
        raise NotImplementedError

    def make_alert(self, flow, alert_type, score, description, evidence=None) -> Alert:
        from models import AlertSeverity
        import config
        return Alert(
            alert_type=alert_type,
            severity=AlertSeverity.from_score(score),
            score=score,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            src_port=flow.src_port, dst_port=flow.dst_port,
            protocol=flow.protocol.value,
            description=f"[Plugin:{self.name}] {description}",
            evidence=evidence or {},
            mitre=config.MITRE_MAPPING.get(alert_type.value, {}),
            flow_id=flow.flow_id,
        )


class PluginManager:
    """Loads, manages, and invokes detection plugins."""

    def __init__(self, plugins_dir: str = PLUGINS_DIR):
        self.plugins_dir = plugins_dir
        self._plugins: List[PluginBase] = []
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(self.plugins_dir):
            return
        for fname in os.listdir(self.plugins_dir):
            if fname.startswith("_") or not fname.endswith(".py"):
                continue
            if fname == "loader.py":
                continue
            self._load_file(os.path.join(self.plugins_dir, fname))

        logger.info(f"Loaded {len(self._plugins)} detection plugin(s)")

    def _load_file(self, path: str):
        try:
            spec   = importlib.util.spec_from_file_location("plugin", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                cls = getattr(module, attr_name)
                if (isinstance(cls, type) and
                        issubclass(cls, PluginBase) and
                        cls is not PluginBase):
                    instance = cls()
                    if instance.enabled:
                        self._plugins.append(instance)
                        logger.info(f"Loaded plugin: {instance.name}")
        except Exception as e:
            logger.error(f"Failed to load plugin {path}: {e}")

    def analyze(self, flow: Flow) -> List[Alert]:
        alerts = []
        for plugin in self._plugins:
            try:
                alerts.extend(plugin.analyze(flow))
            except Exception as e:
                logger.error(f"Plugin {plugin.name} error: {e}")
        return alerts

    def list_plugins(self) -> List[Dict]:
        return [{"name": p.name, "description": p.description} for p in self._plugins]

    def reload(self):
        self._plugins.clear()
        self._load_plugins()
