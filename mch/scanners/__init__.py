"""Core scanner implementations for the MCH project.

This package contains the specific scanner logic for:
- Port scanning (`ports`)
- Directory fuzzing (`fuzz`)
- CORS misconfigurations (`acao`)
"""

from .ports import PortScanner
from .fuzz import FuzzScanner
from .acao import AcaoScanner

#: A registry mapping scan type identifiers to their respective scanner classes.
SCANNERS = {'ports': PortScanner, 'fuzz': FuzzScanner, 'acao': AcaoScanner}
