"""
xclaw-ag-input-guard: Real-time input protection for OpenClaw agents.

This package provides comprehensive input validation and threat detection
to protect OpenClaw agents from prompt injection, jailbreak attempts,
and other malicious user inputs.
"""

from .config import Config
from .detector import InputGuard, DetectionResult
from .interceptor import InputGuardInterceptor

__version__ = "1.0.0"
__author__ = "xclaw"
__email__ = "dev@xclaw.dev"

__all__ = [
    "Config",
    "InputGuard",
    "DetectionResult",
    "InputGuardInterceptor",
]


class InputGuardSkill:
    """
    OpenClaw skill entry point for xclaw-ag-input-guard.
    
    This class provides the standard OpenClaw skill interface for
    registering and configuring the input guard.
    """
    
    name = "xclaw-ag-input-guard"
    version = __version__
    description = "Real-time input protection for OpenClaw agents"
    
    def __init__(self, config: dict = None):
        """
        Initialize the skill with optional configuration.
        
        Args:
            config: Optional configuration dictionary
        """
        from .config import Config
        from .interceptor import InputGuardInterceptor
        
        if config:
            self.config = Config.from_dict(config)
        else:
            self.config = Config()
        
        self.interceptor = InputGuardInterceptor(self.config)
    
    def register(self, openclaw_app):
        """
        Register the skill with an OpenClaw application.
        
        Args:
            openclaw_app: The OpenClaw application instance
        """
        openclaw_app.register_interceptor("user_input", self.interceptor)
    
    def get_interceptor(self):
        """
        Get the input guard interceptor for manual registration.
        
        Returns:
            InputGuardInterceptor instance
        """
        return self.interceptor
