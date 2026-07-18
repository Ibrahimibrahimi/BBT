"""
Dynamic plugin loader.

Scans the `methods/` package for every .py file, imports it, and
collects every class that subclasses BaseMethod. This means adding a
new encoding method is as simple as dropping a new file into
`methods/` — no registration, no editing this file, no editing main.py.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import List

import methods
from methods.base import BaseMethod


def load_methods() -> List[BaseMethod]:
    """
    Import every module inside the methods/ package, find every class
    that inherits from BaseMethod (but isn't BaseMethod itself), and
    return one instance of each. Modules that fail to import are
    skipped with a warning rather than crashing the whole app.
    """
    discovered: List[BaseMethod] = []
    methods_path = Path(methods.__file__).parent

    for module_info in pkgutil.iter_modules([str(methods_path)]):
        module_name = module_info.name

        # skip the base module itself and any private/underscore files
        if module_name in ("base",) or module_name.startswith("_"):
            continue

        full_module_name = f"methods.{module_name}"

        try:
            module = importlib.import_module(full_module_name)
        except Exception as exc:  # noqa: BLE001 - we want to keep going
            print(f"[loader] Skipping '{module_name}': failed to import ({exc})")
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BaseMethod:
                continue
            if issubclass(obj, BaseMethod) and obj.__module__ == full_module_name:
                try:
                    discovered.append(obj())
                except Exception as exc:  # noqa: BLE001
                    print(f"[loader] Skipping class '{obj.__name__}': failed to instantiate ({exc})")

    # Keep results stable and predictable: sort by category then name
    discovered.sort(key=lambda m: (m.category, m.name))
    return discovered
