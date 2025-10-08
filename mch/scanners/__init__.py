from .ports import PortsScanner
from .fuzz import FuzzScanner
from .acao_leak import AcaoLeakScanner
from .acao_weak import AcaoWeakScanner

SCANNERS = {
    "ports": PortsScanner,
    "fuzz": FuzzScanner,
    "acao-leak": AcaoLeakScanner,
    "acao-weak": AcaoWeakScanner,
}
