import asyncio
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
from loguru import logger
from src.database.models import AttackLog, HoneypotSession, get_db_session
from src.llm.service import llm_service
from src.monitoring.metrics import metrics_collector


class BaseHoneypot(ABC):
    """Base class for all honeypot services"""
    
    def __init__(self, name: str, port: int, config: Dict[str, Any]):
        self.name = name
        self.port = port
        self.config = config
        self.server = None
        self.active_sessions = {}
        
    @abstractmethod
    async def start(self):
        """Start the honeypot service"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Stop the honeypot service"""
        pass
    
    async def log_attack(self, source_ip: str, source_port: int, payload: str = "", 
                        attack_type: str = "unknown", session_id: str = None, **kwargs):
        """Log attack to database"""
        try:
            db = get_db_session()
            
            # Create attack log entry
            attack_log = AttackLog(
                source_ip=source_ip,
                source_port=source_port,
                destination_port=self.port,
                protocol=self.name,
                service=self.name,
                attack_type=attack_type,
                payload=payload,
                session_id=session_id,
                **kwargs
            )
            
            # Analyze attack with LLM
            attack_data = {
                "source_ip": source_ip,
                "service": self.name,
                "payload": payload,
                "attack_type": attack_type
            }
            
            analysis = await llm_service.analyze_attack(attack_data)
            attack_log.llm_analysis = analysis
            attack_log.severity = analysis.get("severity", "medium")
            attack_log.confidence_score = analysis.get("confidence", 0.5)
            
            db.add(attack_log)
            db.commit()
            db.close()
            
            # Update metrics
            metrics_collector.increment_attack_counter(self.name, attack_type)
            
            logger.info(f"Attack logged: {source_ip}:{source_port} -> {self.name}:{self.port} ({attack_type})")
            
        except Exception as e:
            logger.error(f"Error logging attack: {e}")
    
    def create_session(self, source_ip: str) -> str:
        """Create new session"""
        session_id = str(uuid.uuid4())
        
        session_data = {
            "id": session_id,
            "source_ip": source_ip,
            "start_time": datetime.now(),
            "commands_count": 0,
            "files_accessed": [],
            "commands_executed": []
        }
        
        self.active_sessions[session_id] = session_data
        
        # Log session to database
        try:
            db = get_db_session()
            session = HoneypotSession(
                session_id=session_id,
                source_ip=source_ip,
                service=self.name
            )
            db.add(session)
            db.commit()
            db.close()
        except Exception as e:
            logger.error(f"Error creating session: {e}")
        
        return session_id
    
    def end_session(self, session_id: str):
        """End session"""
        if session_id in self.active_sessions:
            session_data = self.active_sessions[session_id]
            duration = (datetime.now() - session_data["start_time"]).total_seconds()
            
            # Update database
            try:
                db = get_db_session()
                session = db.query(HoneypotSession).filter(
                    HoneypotSession.session_id == session_id
                ).first()
                
                if session:
                    session.end_time = datetime.now()
                    session.duration = int(duration)
                    session.commands_count = session_data["commands_count"]
                    session.is_active = False
                    db.commit()
                
                db.close()
            except Exception as e:
                logger.error(f"Error ending session: {e}")
            
            del self.active_sessions[session_id]
            logger.info(f"Session ended: {session_id} (duration: {duration:.1f}s)")


class HoneypotManager:
    """Manager for all honeypot services"""
    
    def __init__(self):
        self.honeypots = {}
        self.running = False
    
    def register_honeypot(self, honeypot: BaseHoneypot):
        """Register a honeypot service"""
        self.honeypots[honeypot.name] = honeypot
        logger.info(f"Registered honeypot: {honeypot.name} on port {honeypot.port}")
    
    async def start_all(self):
        """Start all registered honeypots"""
        self.running = True
        tasks = []
        
        for name, honeypot in self.honeypots.items():
            if honeypot.config.get("enabled", True):
                task = asyncio.create_task(honeypot.start())
                tasks.append(task)
                logger.info(f"Starting honeypot: {name}")
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop_all(self):
        """Stop all honeypots"""
        self.running = False
        tasks = []
        
        for name, honeypot in self.honeypots.items():
            task = asyncio.create_task(honeypot.stop())
            tasks.append(task)
            logger.info(f"Stopping honeypot: {name}")
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all honeypots"""
        status = {
            "running": self.running,
            "services": {}
        }
        
        for name, honeypot in self.honeypots.items():
            status["services"][name] = {
                "name": name,
                "port": honeypot.port,
                "enabled": honeypot.config.get("enabled", True),
                "active_sessions": len(honeypot.active_sessions)
            }
        
        return status


# Global honeypot manager
honeypot_manager = HoneypotManager()