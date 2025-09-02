"""
LLM package for honeypot response generation.
"""

from .llm_client import LLMClient
from .prompt_templates import (
    ATTACK_ANALYSIS_PROMPT,
    RESPONSE_GENERATION_PROMPT,
    PATTERN_ANALYSIS_PROMPT,
    HONEYPOT_SYSTEM_PROMPTS,
    DECEPTION_STRATEGIES
)

__all__ = [
    'LLMClient',
    'ATTACK_ANALYSIS_PROMPT',
    'RESPONSE_GENERATION_PROMPT', 
    'PATTERN_ANALYSIS_PROMPT',
    'HONEYPOT_SYSTEM_PROMPTS',
    'DECEPTION_STRATEGIES'
]