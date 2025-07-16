import openai
import json
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import torch
from loguru import logger
from src.core.config import config


class BaseLLMProvider(ABC):
    """Base class for LLM providers"""
    
    @abstractmethod
    async def generate_response(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """Generate response from LLM"""
        pass
    
    @abstractmethod
    async def analyze_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack using LLM"""
        pass


class OpenAIProvider(BaseLLMProvider):
    """OpenAI LLM provider"""
    
    def __init__(self):
        if config.llm.api_key:
            openai.api_key = config.llm.api_key
        else:
            logger.warning("OpenAI API key not provided. LLM features will be limited.")
    
    async def generate_response(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """Generate response using OpenAI"""
        try:
            if not config.llm.api_key:
                return "Command not found."
            
            # Build context-aware prompt
            system_prompt = self._build_system_prompt(context)
            
            response = await openai.ChatCompletion.acreate(
                model=config.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=config.llm.max_tokens,
                temperature=config.llm.temperature
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"Error generating OpenAI response: {e}")
            return "Command not found."
    
    async def analyze_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack using OpenAI"""
        try:
            if not config.llm.api_key:
                return {"analysis": "Limited analysis available", "severity": "medium"}
            
            prompt = self._build_analysis_prompt(attack_data)
            
            response = await openai.ChatCompletion.acreate(
                model=config.llm.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing honeypot attacks. Provide structured analysis in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=config.llm.max_tokens,
                temperature=0.3
            )
            
            try:
                analysis = json.loads(response.choices[0].message.content)
            except json.JSONDecodeError:
                analysis = {
                    "analysis": response.choices[0].message.content,
                    "severity": "medium",
                    "confidence": 0.5
                }
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing attack with OpenAI: {e}")
            return {"analysis": "Analysis failed", "severity": "medium", "confidence": 0.0}
    
    def _build_system_prompt(self, context: Dict[str, Any] = None) -> str:
        """Build system prompt for response generation"""
        base_prompt = """You are simulating a Linux server response. Respond realistically to commands as if you're a real system.
        
Rules:
1. Keep responses short and realistic
2. Simulate appropriate file structures
3. Return realistic system information
4. Behave like a vulnerable but functional system
5. Don't reveal you're a honeypot"""

        if context:
            service = context.get("service", "unknown")
            if service == "ssh":
                base_prompt += "\nYou are responding to SSH commands on a Ubuntu server."
            elif service == "http":
                base_prompt += "\nYou are a web server responding to HTTP requests."
            elif service == "ftp":
                base_prompt += "\nYou are an FTP server responding to file transfer commands."
        
        return base_prompt
    
    def _build_analysis_prompt(self, attack_data: Dict[str, Any]) -> str:
        """Build prompt for attack analysis"""
        return f"""Analyze this honeypot attack data and provide a JSON response with the following fields:
- analysis: Brief description of the attack
- attack_type: Type of attack (e.g., "brute_force", "command_injection", "reconnaissance")
- severity: "low", "medium", "high", or "critical"
- confidence: Float between 0.0 and 1.0
- indicators: List of notable indicators
- recommendations: List of security recommendations

Attack Data:
Source IP: {attack_data.get('source_ip', 'unknown')}
Service: {attack_data.get('service', 'unknown')}
Payload: {attack_data.get('payload', 'none')}
Commands: {attack_data.get('commands', [])}
User Agent: {attack_data.get('user_agent', 'none')}"""


class HuggingFaceProvider(BaseLLMProvider):
    """Hugging Face local LLM provider"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.generator = None
        self._load_model()
    
    def _load_model(self):
        """Load Hugging Face model"""
        try:
            model_name = "microsoft/DialoGPT-small"  # Lightweight model for responses
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForCausalLM.from_pretrained(model_name)
            
            # Set pad token
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            logger.info(f"Loaded Hugging Face model: {model_name}")
        except Exception as e:
            logger.error(f"Error loading Hugging Face model: {e}")
    
    async def generate_response(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """Generate response using Hugging Face model"""
        try:
            if not self.model or not self.tokenizer:
                return "Command not found."
            
            # Simple command responses for SSH-like interactions
            simple_responses = {
                "ls": "file1.txt  file2.log  directory1/",
                "pwd": "/home/user",
                "whoami": "user",
                "ps": "PID TTY TIME CMD\n1234 pts/0 00:00:01 bash",
                "uname": "Linux ubuntu 5.4.0-91-generic x86_64 GNU/Linux",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"
            }
            
            # Check for simple commands first
            prompt_lower = prompt.lower().strip()
            for cmd, response in simple_responses.items():
                if prompt_lower.startswith(cmd):
                    return response
            
            # For complex prompts, use the model
            inputs = self.tokenizer.encode(prompt, return_tensors="pt", truncation=True, max_length=100)
            
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs,
                    max_length=inputs.shape[1] + 50,
                    num_return_sequences=1,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Extract only the new part
            response = response[len(prompt):].strip()
            
            return response if response else "Command not found."
        
        except Exception as e:
            logger.error(f"Error generating Hugging Face response: {e}")
            return "Command not found."
    
    async def analyze_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack using simple heuristics"""
        try:
            analysis = {
                "analysis": "Attack detected and logged",
                "attack_type": "unknown",
                "severity": "medium",
                "confidence": 0.6,
                "indicators": [],
                "recommendations": ["Monitor this IP address", "Review security policies"]
            }
            
            # Simple heuristic analysis
            payload = attack_data.get("payload", "").lower()
            commands = attack_data.get("commands", [])
            
            # Check for common attack patterns
            if any(term in payload for term in ["rm -rf", "wget", "curl", "/etc/passwd"]):
                analysis["attack_type"] = "command_injection"
                analysis["severity"] = "high"
                analysis["confidence"] = 0.8
            elif any(term in payload for term in ["admin", "root", "password"]):
                analysis["attack_type"] = "brute_force"
                analysis["severity"] = "medium"
            elif len(commands) > 10:
                analysis["attack_type"] = "reconnaissance"
                analysis["severity"] = "medium"
            
            return analysis
        
        except Exception as e:
            logger.error(f"Error analyzing attack: {e}")
            return {"analysis": "Analysis failed", "severity": "medium", "confidence": 0.0}


class LLMService:
    """LLM service manager"""
    
    def __init__(self):
        self.provider = self._initialize_provider()
    
    def _initialize_provider(self) -> BaseLLMProvider:
        """Initialize LLM provider based on configuration"""
        provider_name = config.llm.provider.lower()
        
        if provider_name == "openai":
            return OpenAIProvider()
        elif provider_name == "huggingface":
            return HuggingFaceProvider()
        else:
            logger.warning(f"Unknown LLM provider: {provider_name}. Using Hugging Face as default.")
            return HuggingFaceProvider()
    
    async def generate_response(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """Generate response using configured LLM provider"""
        return await self.provider.generate_response(prompt, context)
    
    async def analyze_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack using configured LLM provider"""
        return await self.provider.analyze_attack(attack_data)


# Global LLM service instance
llm_service = LLMService()