"""
Spectra Client SDK (Legacy Alias) -> Proxynth Client SDK
Maintained for backwards-compatibility with existing scripts.
"""

from proxynth_client import ProxynthSession, SpectraSession, PROXSYNTH_PROXY_PORT, PROXSYNTH_PROXY_URL, PROXSYNTH_PROJECT, PROXSYNTH_BACKEND_URL

SPECTRA_PROXY_PORT = PROXSYNTH_PROXY_PORT
SPECTRA_PROXY_URL = PROXSYNTH_PROXY_URL
SPECTRA_PROJECT = PROXSYNTH_PROJECT
SPECTRA_BACKEND_URL = PROXSYNTH_BACKEND_URL

__all__ = ["ProxynthSession", "SpectraSession", "SPECTRA_PROXY_PORT", "SPECTRA_PROXY_URL", "SPECTRA_PROJECT", "SPECTRA_BACKEND_URL"]
