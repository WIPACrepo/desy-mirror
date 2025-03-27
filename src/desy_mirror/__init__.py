try:
    from .version import __version__
except ImportError:
    # package is not installed
    __version__ = None
