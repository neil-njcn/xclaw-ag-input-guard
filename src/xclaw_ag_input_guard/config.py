"""
Configuration management for xclaw-ag-input-guard.

This module provides configuration loading, validation, and management
for the input guard system.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


@dataclass
class Config:
    """
    Configuration for the input guard system.
    
    Attributes:
        threshold: Detection threshold (0.0 - 1.0). Higher values = more strict.
        action: Action to take on detection: "block", "warn", or "log"
        detectors: Dictionary of detector names to enabled status
        logging: Logging configuration dictionary
    """
    
    threshold: float = 0.7
    action: str = "block"
    detectors: Dict[str, bool] = field(default_factory=lambda: {
        "prompt_injection": True,
        "jailbreak": True,
        "agent_hijacking": True,
    })
    logging: Dict[str, Any] = field(default_factory=lambda: {
        "level": "INFO",
        "file": "logs/input-guard.log",
        "max_size": "10MB",
        "backup_count": 5,
    })
    
    def __post_init__(self):
        """Validate configuration values."""
        # Validate threshold
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError(f"Threshold must be between 0.0 and 1.0, got {self.threshold}")
        
        # Validate action
        valid_actions = ["block", "warn", "log"]
        if self.action not in valid_actions:
            raise ValueError(f"Action must be one of {valid_actions}, got {self.action}")
        
        # Validate detectors
        valid_detectors = ["prompt_injection", "jailbreak", "agent_hijacking"]
        for detector in self.detectors:
            if detector not in valid_detectors:
                raise ValueError(f"Unknown detector: {detector}")
    
    @classmethod
    def from_file(cls, path: str) -> "Config":
        """
        Load configuration from a YAML file.
        
        Args:
            path: Path to the YAML configuration file
            
        Returns:
            Config instance loaded from file
            
        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            ValueError: If the configuration is invalid
        """
        path = Path(path)
        
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if data is None:
            data = {}
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """
        Create configuration from a dictionary.
        
        Args:
            data: Dictionary containing configuration values
            
        Returns:
            Config instance
        """
        # Create default instance to get default values
        defaults = cls()
        
        # Extract values with defaults
        threshold = data.get('threshold', defaults.threshold)
        action = data.get('action', defaults.action)
        
        # Merge detectors with defaults
        detectors = dict(defaults.detectors)
        if 'detectors' in data:
            detectors.update(data['detectors'])
        
        # Merge logging with defaults
        logging = dict(defaults.logging)
        if 'logging' in data:
            logging.update(data['logging'])
        
        return cls(
            threshold=threshold,
            action=action,
            detectors=detectors,
            logging=logging,
        )
    
    @classmethod
    def from_env(cls) -> "Config":
        """
        Load configuration from environment variables.
        
        Environment variables:
            XCLAW_INPUT_GUARD_THRESHOLD: Detection threshold
            XCLAW_INPUT_GUARD_ACTION: Action mode (block/warn/log)
            XCLAW_INPUT_GUARD_CONFIG: Path to config file
            
        Returns:
            Config instance
        """
        # Check for config file path
        config_path = os.environ.get('XCLAW_INPUT_GUARD_CONFIG')
        if config_path:
            return cls.from_file(config_path)
        
        # Build from environment variables
        data: Dict[str, Any] = {}
        
        if 'XCLAW_INPUT_GUARD_THRESHOLD' in os.environ:
            data['threshold'] = float(os.environ['XCLAW_INPUT_GUARD_THRESHOLD'])
        
        if 'XCLAW_INPUT_GUARD_ACTION' in os.environ:
            data['action'] = os.environ['XCLAW_INPUT_GUARD_ACTION']
        
        # Detector settings
        detectors = {}
        if os.environ.get('XCLAW_INPUT_GUARD_ENABLE_PROMPT_INJECTION', '').lower() == 'true':
            detectors['prompt_injection'] = True
        if os.environ.get('XCLAW_INPUT_GUARD_ENABLE_JAILBREAK', '').lower() == 'true':
            detectors['jailbreak'] = True
        if os.environ.get('XCLAW_INPUT_GUARD_ENABLE_AGENT_HIJACKING', '').lower() == 'true':
            detectors['agent_hijacking'] = True
        
        if detectors:
            data['detectors'] = detectors
        
        return cls.from_dict(data)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            'threshold': self.threshold,
            'action': self.action,
            'detectors': dict(self.detectors),
            'logging': dict(self.logging),
        }
    
    def is_detector_enabled(self, detector_name: str) -> bool:
        """
        Check if a specific detector is enabled.
        
        Args:
            detector_name: Name of the detector
            
        Returns:
            True if the detector is enabled, False otherwise
        """
        return self.detectors.get(detector_name, False)
    
    def get_enabled_detectors(self) -> list:
        """
        Get list of enabled detector names.
        
        Returns:
            List of enabled detector names
        """
        return [name for name, enabled in self.detectors.items() if enabled]
