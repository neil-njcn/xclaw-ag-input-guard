"""
OpenClaw message interception for input protection.

This module provides the integration point with OpenClaw's message
processing pipeline, intercepting user input before it reaches
the agent's core logic.
"""

import logging
from typing import Any, Callable, Dict, Optional

from .config import Config
from .detector import DetectionResult, InputGuard


class InputGuardInterceptor:
    """
    Interceptor for OpenClaw user input messages.
    
    This class implements the OpenClaw interceptor interface to
    hook into the message processing pipeline and provide real-time
    input protection.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the interceptor.
        
        Args:
            config: Configuration object. If None, uses default configuration.
        """
        self.config = config or Config()
        self.guard = InputGuard(self.config)
        self.logger = logging.getLogger(__name__)
        self._on_block: Optional[Callable] = None
        self._on_warn: Optional[Callable] = None
    
    def on_user_input(self, message: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process user input through the input guard.
        
        This method is called by OpenClaw for each user input message.
        It analyzes the input for threats and returns a result dict
        that controls how OpenClaw processes the message.
        
        Args:
            message: The user input message
            context: Context dictionary with metadata (user_id, session_id, etc.)
            
        Returns:
            Dictionary with processing instructions:
            - {"blocked": True, "reason": result} - Block the input
            - {"warning": result, "proceed": True} - Allow with warning
            - {"proceed": True} - Allow normally
        """
        self.logger.debug(f"Checking input: {message[:100]}...")
        
        # Run detection
        result = self.guard.check(message, context)
        
        # Handle based on detection result and configured action
        if result.detected and result.confidence >= self.config.threshold:
            self.logger.warning(
                f"Threat detected: {result.threat_type} "
                f"(confidence: {result.confidence:.2f})"
            )
            
            if self.config.action == "block":
                return self._handle_block(result, context)
            elif self.config.action == "warn":
                return self._handle_warn(result, context)
            elif self.config.action == "log":
                return self._handle_log(result, context)
        
        # No threat detected or below threshold
        return {"proceed": True}
    
    def _handle_block(
        self,
        result: DetectionResult,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle block action.
        
        Args:
            result: Detection result
            context: Context dictionary
            
        Returns:
            Block response dictionary
        """
        self.logger.info(
            f"Blocking input from user {context.get('user_id', 'unknown')}: "
            f"{result.threat_type}"
        )
        
        # Call block callback if registered
        if self._on_block:
            try:
                self._on_block(result, context)
            except Exception as e:
                self.logger.error(f"Block callback failed: {e}")
        
        return {
            "blocked": True,
            "reason": result.to_dict(),
        }
    
    def _handle_warn(
        self,
        result: DetectionResult,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle warn action.
        
        Args:
            result: Detection result
            context: Context dictionary
            
        Returns:
            Warning response dictionary
        """
        self.logger.info(
            f"Warning for input from user {context.get('user_id', 'unknown')}: "
            f"{result.threat_type}"
        )
        
        # Call warn callback if registered
        if self._on_warn:
            try:
                self._on_warn(result, context)
            except Exception as e:
                self.logger.error(f"Warn callback failed: {e}")
        
        return {
            "warning": result.to_dict(),
            "proceed": True,
        }
    
    def _handle_log(
        self,
        result: DetectionResult,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle log action.
        
        Args:
            result: Detection result
            context: Context dictionary
            
        Returns:
            Log response dictionary (allows processing)
        """
        self.logger.info(
            f"Logging threat from user {context.get('user_id', 'unknown')}: "
            f"{result.threat_type} (confidence: {result.confidence:.2f})"
        )
        
        # Just log and allow
        return {"proceed": True}
    
    def set_block_callback(self, callback: Callable[[DetectionResult, Dict], None]) -> None:
        """
        Set a callback to be called when input is blocked.
        
        Args:
            callback: Function to call with (result, context) arguments
        """
        self._on_block = callback
    
    def set_warn_callback(self, callback: Callable[[DetectionResult, Dict], None]) -> None:
        """
        Set a callback to be called when input triggers a warning.
        
        Args:
            callback: Function to call with (result, context) arguments
        """
        self._on_warn = callback
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get interceptor statistics.
        
        Returns:
            Dictionary with statistics
        """
        return self.guard.get_detector_status()


# Convenience function for direct usage
def create_interceptor(
    config_path: Optional[str] = None,
    config_dict: Optional[Dict[str, Any]] = None
) -> InputGuardInterceptor:
    """
    Create an interceptor with configuration.
    
    Args:
        config_path: Optional path to configuration file
        config_dict: Optional configuration dictionary
        
    Returns:
        Configured InputGuardInterceptor
        
    Raises:
        ValueError: If both config_path and config_dict are provided
    """
    if config_path is not None and config_dict is not None:
        raise ValueError("Cannot specify both config_path and config_dict")
    
    if config_path is not None:
        config = Config.from_file(config_path)
    elif config_dict is not None:
        config = Config.from_dict(config_dict)
    else:
        config = Config()
    
    return InputGuardInterceptor(config)
