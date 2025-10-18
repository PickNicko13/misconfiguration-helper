from .ports import PortScanner
from .fuzz import FuzzScanner
from .acao import AcaoScanner

SCANNERS = {
    "ports": PortScanner,
    "fuzz": FuzzScanner,
    "acao": AcaoScanner
}
