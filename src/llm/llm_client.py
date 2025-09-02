"""
LLM client for generating dynamic responses.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class LLMClient:
    """Client for interacting with Large Language Models."""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger('honeypot.llm')
        self.setup_client()
        
    def setup_client(self) -> None:
        """Initialize the LLM client."""
        if not OPENAI_AVAILABLE:
            self.logger.warning("OpenAI library not available. LLM features disabled.")
            self.client = None
            return
            
        provider = self.config.get('honeypot.llm.provider', 'openai')
        
        if provider == 'openai':
            api_key = self.config.llm_api_key
            if not api_key:
                self.logger.warning("OpenAI API key not found. LLM responses disabled.")
                self.client = None
                return
                
            openai.api_key = api_key
            self.client = openai
        else:
            self.logger.error(f"Unsupported LLM provider: {provider}")
            self.client = None
            
    async def generate_response(self, attack_info: Dict[str, Any]) -> Optional[str]:
        """Generate a dynamic response using LLM."""
        if not self.client:
            return None
            
        try:
            prompt = self._build_prompt(attack_info)
            
            response = await asyncio.to_thread(
                self.client.ChatCompletion.create,
                model=self.config.get('honeypot.llm.model', 'gpt-3.5-turbo'),
                messages=[
                    {"role": "system", "content": "You are an industrial control system that appears vulnerable but is actually a honeypot. Generate realistic responses that keep attackers engaged while gathering intelligence."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.config.get('honeypot.llm.max_tokens', 500),
                temperature=self.config.get('honeypot.llm.temperature', 0.7)
            )
            
            generated_response = response.choices[0].message.content.strip()
            self.logger.info(f"Generated LLM response for {attack_info.get('type', 'unknown')} attack")
            
            return generated_response
            
        except Exception as e:
            self.logger.error(f"Failed to generate LLM response: {e}")
            return None
            
    def _build_prompt(self, attack_info: Dict[str, Any]) -> str:
        """Build prompt for LLM based on attack information."""
        attack_type = attack_info.get('type', 'unknown')
        
        # Get appropriate prompt template
        if attack_type in ['sql_injection', 'xss', 'command_injection']:
            template = self.config.get_prompt_template('attack_analysis')
        else:
            template = self.config.get_prompt_template('response_generation')
            
        # Fill template with attack information
        prompt = template.format(
            attack_type=attack_type,
            source_ip=attack_info.get('source_ip', 'unknown'),
            target=f"{attack_info.get('target_port', 'unknown')}",
            payload=attack_info.get('payload', '')[:500],  # Limit payload length
            timestamp=datetime.utcnow().isoformat(),
            context=attack_info.get('context', 'Industrial control system'),
            system_type=attack_info.get('system_type', 'SCADA/HMI')
        )
        
        return prompt
        
    async def analyze_attack_pattern(self, attacks: List[Dict[str, Any]]) -> Optional[str]:
        """Analyze multiple attacks to identify patterns."""
        if not self.client or not attacks:
            return None
            
        try:
            # Build analysis prompt
            attack_summary = "\n".join([
                f"- {attack.get('type', 'unknown')} from {attack.get('source_ip', 'unknown')} "
                f"at {attack.get('timestamp', 'unknown')}"
                for attack in attacks[-10:]  # Last 10 attacks
            ])
            
            prompt = f"""
            Analyze these recent attack patterns on an industrial control system:
            
            {attack_summary}
            
            Provide a brief analysis of:
            1. Attack sophistication level
            2. Likely attacker motivation
            3. Recommended deception strategy
            
            Keep response under 200 words.
            """
            
            response = await asyncio.to_thread(
                self.client.ChatCompletion.create,
                model=self.config.get('honeypot.llm.model', 'gpt-3.5-turbo'),
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst specializing in industrial control systems."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.3
            )
            
            analysis = response.choices[0].message.content.strip()
            self.logger.info("Generated attack pattern analysis")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze attack patterns: {e}")
            return None