"""
Input detection logic using xclaw-agentguard framework.

This module provides the core detection capabilities for identifying
malicious user inputs including prompt injection, jailbreak attempts,
and agent hijacking.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Import detectors from xclaw-agentguard framework
try:
    from xclaw_agentguard import (
        AgentHijackingDetector,
        JailbreakDetector,
        PromptInjectionDetector,
    )
    XCLAW_AGENTGUARD_AVAILABLE = True
except ImportError:
    XCLAW_AGENTGUARD_AVAILABLE = False
    # Define placeholder classes for when xclaw-agentguard is not installed
    class PromptInjectionDetector:
        def detect(self, text: str) -> Dict[str, Any]:
            return {"detected": False, "confidence": 0.0, "patterns": []}
    
    class JailbreakDetector:
        def detect(self, text: str) -> Dict[str, Any]:
            return {"detected": False, "confidence": 0.0, "patterns": []}
    
    class AgentHijackingDetector:
        def detect(self, text: str) -> Dict[str, Any]:
            return {"detected": False, "confidence": 0.0, "patterns": []}

from .config import Config


@dataclass
class DetectionResult:
    """
    Result of input analysis.
    
    Attributes:
        is_safe: True if input is safe, False if threat detected
        detected: True if any threat was detected
        confidence: Confidence score (0.0 - 1.0)
        threat_type: Type of threat detected, or None
        action: Action taken: "block", "warn", "log", or "allow"
        reason: Human-readable reason for the decision
        details: Additional detection details
    """
    
    is_safe: bool = True
    detected: bool = False
    confidence: float = 0.0
    threat_type: Optional[str] = None
    action: str = "allow"
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'is_safe': self.is_safe,
            'detected': self.detected,
            'confidence': self.confidence,
            'threat_type': self.threat_type,
            'action': self.action,
            'reason': self.reason,
            'details': self.details,
        }


class InputGuard:
    """
    Main class for input validation and threat detection.
    
    This class orchestrates multiple detectors to provide comprehensive
    input protection for OpenClaw agents.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the input guard.
        
        Args:
            config: Configuration object. If None, uses default configuration.
        """
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        
        # Initialize detectors
        self._detectors: Dict[str, Any] = {}
        self._init_detectors()
    
    def _init_detectors(self) -> None:
        """Initialize enabled detectors."""
        if not XCLAW_AGENTGUARD_AVAILABLE:
            self.logger.warning(
                "xclaw-agentguard not installed. Using fallback detection."
            )
        
        # Initialize prompt injection detector
        if self.config.is_detector_enabled('prompt_injection'):
            self._detectors['prompt_injection'] = PromptInjectionDetector()
            self.logger.debug("Initialized PromptInjectionDetector")
        
        # Initialize jailbreak detector
        if self.config.is_detector_enabled('jailbreak'):
            self._detectors['jailbreak'] = JailbreakDetector()
            self.logger.debug("Initialized JailbreakDetector")
        
        # Initialize agent hijacking detector
        if self.config.is_detector_enabled('agent_hijacking'):
            self._detectors['agent_hijacking'] = AgentHijackingDetector()
            self.logger.debug("Initialized AgentHijackingDetector")
    
    def check(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Check a message for threats.
        
        Args:
            message: The user input message to check
            context: Optional context dictionary (user_id, session_id, etc.)
            
        Returns:
            DetectionResult with analysis results
        """
        if not message or not message.strip():
            # Empty messages are safe
            return DetectionResult(
                is_safe=True,
                detected=False,
                confidence=0.0,
                action="allow",
                reason="Empty message",
            )
        
        # Run all enabled detectors
        all_results = []
        
        for detector_name, detector in self._detectors.items():
            try:
                result = detector.detect(message)
                all_results.append({
                    'detector': detector_name,
                    'detected': result.get('detected', False),
                    'confidence': result.get('confidence', 0.0),
                    'patterns': result.get('patterns', []),
                    'details': result,
                })
            except Exception as e:
                self.logger.error(f"Detector {detector_name} failed: {e}")
                # Continue with other detectors
        
        # Combine results
        return self._combine_results(all_results, context)
    
    def check_batch(self, messages: List[str]) -> List[DetectionResult]:
        """
        Check multiple messages for threats.
        
        Args:
            messages: List of messages to check
            
        Returns:
            List of DetectionResult objects
        """
        return [self.check(msg) for msg in messages]
    
    def _combine_results(
        self,
        detector_results: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Combine results from multiple detectors.
        
        Args:
            detector_results: List of detector results
            context: Optional context dictionary
            
        Returns:
            Combined DetectionResult
        """
        if not detector_results:
            # No detectors enabled
            return DetectionResult(
                is_safe=True,
                detected=False,
                confidence=0.0,
                action="allow",
                reason="No detectors enabled",
            )
        
        # Find the highest confidence detection
        max_confidence = 0.0
        detected_threats = []
        
        for result in detector_results:
            if result['detected']:
                detected_threats.append(result)
                if result['confidence'] > max_confidence:
                    max_confidence = result['confidence']
        
        # Determine if threat is detected based on threshold
        is_detected = max_confidence >= self.config.threshold
        
        if not is_detected:
            return DetectionResult(
                is_safe=True,
                detected=False,
                confidence=max_confidence,
                action="allow",
                reason="No threats detected above threshold",
                details={
                    'detector_results': detector_results,
                    'threshold': self.config.threshold,
                },
            )
        
        # Determine primary threat type
        if detected_threats:
            # Sort by confidence
            detected_threats.sort(key=lambda x: x['confidence'], reverse=True)
            primary_threat = detected_threats[0]
            threat_type = primary_threat['detector']
            confidence = primary_threat['confidence']
        else:
            threat_type = "unknown"
            confidence = max_confidence
        
        # Determine action based on configuration
        action = self.config.action
        
        # Build reason string
        if detected_threats:
            reasons = [f"{t['detector']} (confidence: {t['confidence']:.2f})" 
                      for t in detected_threats]
            reason = f"Detected: {', '.join(reasons)}"
        else:
            reason = f"Threat detected with confidence {confidence:.2f}"
        
        # Determine if safe based on action
        is_safe = action == "log" or (action == "warn" and confidence < 0.9)
        
        return DetectionResult(
            is_safe=is_safe,
            detected=True,
            confidence=confidence,
            threat_type=threat_type,
            action=action,
            reason=reason,
            details={
                'detector_results': detector_results,
                'detected_threats': detected_threats,
                'threshold': self.config.threshold,
                'context': context,
            },
        )
    
    def get_detector_status(self) -> Dict[str, Any]:
        """
        Get status of all detectors.
        
        Returns:
            Dictionary with detector status information
        """
        return {
            'available': XCLAW_AGENTGUARD_AVAILABLE,
            'enabled_detectors': list(self._detectors.keys()),
            'config': self.config.to_dict(),
        }
