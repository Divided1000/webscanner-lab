"""
Scan configuration: which endpoints/parameters each check probes.

Keeping this separate from the check logic means the scanner can be pointed at
a different app by editing config (or loading a profile) rather than editing
code — closer to how real DAST tooling is configured per target.
"""

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    # SQL injection / auth endpoint
    login_path: str = "/login"
    username_param: str = "username"
    password_param: str = "password"

    # Reflected XSS endpoint
    search_path: str = "/search"
    search_param: str = "q"

    # IDOR / object-access endpoint; {id} is substituted
    object_path_template: str = "/account/{id}"
    object_ids: tuple = (1, 2, 3)

    # Security-headers check target
    root_path: str = "/"


DEFAULT_CONFIG = ScanConfig()
