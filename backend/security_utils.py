"""
Spectra MCP - Core Security Utilities
Provides authenticated credential encryption, SSRF protection, shell command safe-mode guardrails,
and header/filename sanitization.
"""

import os
import re
import base64
import hashlib
import ipaddress
import urllib.parse
from typing import Tuple, Optional
from cryptography.fernet import Fernet

# ==============================================================================
# 1. Credential Encryption Engine (Fernet AES-128-CBC + HMAC-SHA256)
# ==============================================================================

_KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".spectra_key")

def _get_or_create_fernet_key() -> bytes:
    """Retrieves encryption key from environment, key file, or generates a persistent one."""
    env_secret = os.getenv("SPECTRA_SECRET_KEY")
    if env_secret and env_secret.strip():
        # Derive 32-byte url-safe base64 key using SHA-256
        derived = hashlib.sha256(env_secret.strip().encode("utf-8")).digest()
        return base64.urlsafe_b64encode(derived)

    # Check local key file
    if os.path.exists(_KEY_FILE):
        try:
            with open(_KEY_FILE, "rb") as f:
                key = f.read().strip()
                if len(key) == 44:  # Standard Fernet key length
                    return key
        except Exception:
            pass

    # Generate and persist a new key
    new_key = Fernet.generate_key()
    try:
        with open(_KEY_FILE, "wb") as f:
            f.write(new_key)
        # Set restrictive file permissions on Unix if available
        if hasattr(os, "chmod"):
            os.chmod(_KEY_FILE, 0o600)
    except Exception:
        pass
    return new_key

_FERNET_INSTANCE: Optional[Fernet] = None

def _get_fernet() -> Fernet:
    global _FERNET_INSTANCE
    if _FERNET_INSTANCE is None:
        _FERNET_INSTANCE = Fernet(_get_or_create_fernet_key())
    return _FERNET_INSTANCE


def get_or_create_encryption_key() -> bytes:
    """Public helper to initialize and return the master Fernet encryption key."""
    return _get_or_create_fernet_key()


def encrypt_secret(plaintext: str) -> str:
    """Encrypts sensitive session data/token string and prefixes with 'ENC:'."""
    if not plaintext:
        return ""
    try:
        f = _get_fernet()
        encrypted_bytes = f.encrypt(plaintext.encode("utf-8"))
        return f"ENC:{encrypted_bytes.decode('utf-8')}"
    except Exception:
        return plaintext


def decrypt_secret(stored_text: str) -> str:
    """Decrypts ciphertext if encrypted with 'ENC:', otherwise returns as-is for backward compatibility."""
    if not stored_text:
        return ""
    if stored_text.startswith("ENC:"):
        token = stored_text[4:].strip()
        try:
            f = _get_fernet()
            decrypted_bytes = f.decrypt(token.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except Exception:
            return ""
    return stored_text


# ==============================================================================
# 2. SSRF & Dangerous Network Target Guardrail
# ==============================================================================

# Dangerous IP ranges that must be blocked unless explicitly permitted
_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # AWS/Azure/GCP/OpenStack Instance Metadata Service (IMDS)
]

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

def check_ssrf_safety(url: str, allow_internal: bool = False, spectra_backend_port: int = 8000) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a target URL poses an SSRF threat.
    - Always blocks Cloud Metadata (169.254.169.254).
    - Always blocks recursive self-loopback requests to Spectra's own backend port.
    - Blocks private networks (RFC1918) unless allow_internal=True.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as ex:
        return False, f"Malformed URL: {str(ex)}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ["http", "https"]:
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "Target URL is missing a valid hostname."

    port = parsed.port or (443 if scheme == "https" else 80)

    # 1. Anti-Self-Loopback: Prevent recursive infinite loops back to Spectra
    if hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] and port == spectra_backend_port:
        return False, f"Recursive proxy loop blocked: Target points to Spectra's own port ({spectra_backend_port})."

    # 2. Check if hostname is an IP address or resolves to IP
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        ip_obj = None

    if is_ip and ip_obj:
        # Check Cloud Metadata (Strictly blocked under all circumstances)
        for meta_net in _METADATA_NETWORKS:
            if ip_obj in meta_net:
                return False, f"SSRF Guardrail: Target IP '{hostname}' belongs to cloud instance metadata service (169.254.x.x)."

        # Check Private Networks (Blocked unless allow_internal is enabled)
        if not allow_internal:
            for priv_net in _PRIVATE_NETWORKS:
                if ip_obj in priv_net:
                    return False, f"SSRF Guardrail: Target IP '{hostname}' is in private/loopback network. Enable 'Allow Internal Scope' in project settings to permit."

    # 3. Check for obvious metadata hostname aliases
    if hostname in ["metadata.google.internal", "instance-data", "metadata"]:
        return False, f"SSRF Guardrail: Target host '{hostname}' matches cloud metadata service."

    return True, None


# ==============================================================================
# 3. Hardened CLI Safe-Mode Engine (Windows + Unix)
# ==============================================================================

EXPANDED_DANGEROUS_PATTERNS = [
    # POSIX File system destruction
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\/",
    r"rm\s+(-[rfRF]+\s+|--recursive\s+|--force\s+)*\*",
    r"mkfs",
    r"dd\s+if=",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"\$0\|\$0&",
    r">\s*\/dev\/sd[a-z]",
    r"chmod\s+(-[rR]+\s+)?777\s+\/",
    r"chown\s+(-[rR]+\s+)?.*\/",
    r"find\s+\/\s+-delete",
    
    # Windows File system destruction
    r"format\s+[a-zA-Z]:",
    r"rd\s+(\/s|\/q|\s+)*[a-zA-Z]:\\",
    r"rmdir\s+(\/s|\/q|\s+)*[a-zA-Z]:\\",
    r"del\s+(\/[sfqa]+\s+)*[a-zA-Z]:\\",
    r"Remove-Item\s+(-Recurse|-Force|\s+)*[a-zA-Z]:\\",
    r"Clear-Disk",
    r"Format-Volume",
    
    # Remote pipeline execution
    r"curl\s+[^\n|]+\|\s*(bash|sh|zsh|powershell|cmd)",
    r"wget\s+[^\n|]+\|\s*(bash|sh|zsh|powershell|cmd)",
    r"iwr\s+[^\n|]+\|\s*iex",
    
    # Database destruction
    r"DROP\s+DATABASE",
    r"DROP\s+TABLE",
    r"TRUNCATE\s+TABLE",
    
    # Machine power operations
    r"shutdown(\.exe)?\s+",
    r"reboot(\.exe)?",
    r"init\s+[06]",
    r"Stop-Computer",
    r"Restart-Computer",
]

def check_command_safe_mode(command: str) -> Tuple[bool, Optional[str]]:
    """Inspects shell commands against expanded cross-platform dangerous pattern signatures."""
    cmd_clean = command.strip()
    if not cmd_clean:
        return False, "Command cannot be empty"

    for pat in EXPANDED_DANGEROUS_PATTERNS:
        if re.search(pat, cmd_clean, re.IGNORECASE):
            return False, f"Command blocked by Spectra CLI Safe-Mode (Matched dangerous signature: '{pat}')"

    return True, None


# ==============================================================================
# 4. Header & Filename Sanitizer
# ==============================================================================

def sanitize_attachment_filename(name: str, ext: str = "txt") -> str:
    """Sanitizes strings for safe inclusion in HTTP Content-Disposition headers."""
    clean = re.sub(r"[^a-zA-Z0-9_\-]", "_", name).strip("_")
    if not clean:
        clean = "export"
    clean_ext = re.sub(r"[^a-zA-Z0-9]", "", ext).strip()
    return f"{clean}.{clean_ext}" if clean_ext else clean
