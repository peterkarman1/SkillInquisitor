from importlib import import_module


def test_package_imports():
    module = import_module("skillinquisitor")
    assert getattr(module, "__version__")
