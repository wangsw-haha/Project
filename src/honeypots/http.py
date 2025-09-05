import asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from typing import Dict, Any
import socket
import threading
from loguru import logger
from src.core.honeypot import BaseHoneypot
from src.llm.service import llm_service


class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("http", config.get("port", 80), config)
        self.app = FastAPI()
        self.server_thread = None
        self.setup_routes()
        
        # Fake web application structure
        self.fake_pages = {
            "/": self._generate_index_page(),
            "/admin": self._generate_admin_page(),
            "/login": self._generate_login_page(),
            "/api/users": self._generate_users_api(),
            "/config": self._generate_config_page(),
            "/dashboard": self._generate_dashboard_page(),
            "/phpmyadmin": self._generate_phpmyadmin_page(),
            "/wordpress/wp-admin": self._generate_wordpress_admin(),
        }
        
        # Common vulnerable endpoints
        self.vulnerable_endpoints = [
            "/admin/login",
            "/wp-admin",
            "/phpmyadmin",
            "/api/v1",
            "/config.php",
            "/.env",
            "/backup.sql",
            "/admin.php",
            "/index.php?id=1'",
            "/search?q=<script>alert(1)</script>"
        ]
    
    def setup_routes(self):
        """Setup HTTP routes"""
        
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            # Get client IP
            client_ip = request.client.host
            if "x-forwarded-for" in request.headers:
                client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
            
            # Log the request
            await self.log_attack(
                client_ip,
                request.client.port,
                payload=f"{request.method} {request.url.path}?{request.url.query}",
                attack_type="http_request",
                user_agent=request.headers.get("user-agent", "unknown")
            )
            
            response = await call_next(request)
            return response
        
        @self.app.get("/")
        async def root(request: Request):
            return HTMLResponse(self.fake_pages["/"])
        
        @self.app.get("/admin")
        async def admin(request: Request):
            return HTMLResponse(self.fake_pages["/admin"])
        
        @self.app.get("/login")
        @self.app.post("/login")
        async def login(request: Request):
            if request.method == "POST":
                # Log login attempt
                try:
                    body = await request.body()
                    await self.log_attack(
                        request.client.host,
                        request.client.port,
                        payload=body.decode('utf-8', errors='ignore'),
                        attack_type="http_login_attempt",
                        user_agent=request.headers.get("user-agent", "unknown")
                    )
                except:
                    pass
            
            return HTMLResponse(self.fake_pages["/login"])
        
        @self.app.get("/api/{path:path}")
        async def api_endpoints(request: Request, path: str):
            # Simulate API endpoints
            await self.log_attack(
                request.client.host,
                request.client.port,
                payload=f"API access: {path}",
                attack_type="api_access",
                user_agent=request.headers.get("user-agent", "unknown")
            )
            
            if "users" in path:
                return JSONResponse(self.fake_pages["/api/users"])
            else:
                return JSONResponse({"error": "Not found"}, status_code=404)
        
        @self.app.get("/{path:path}")
        async def catch_all(request: Request, path: str):
            # Check if it's a known vulnerable endpoint
            full_path = f"/{path}"
            
            # Detect potential attacks
            attack_type = "http_request"
            if any(vuln in full_path.lower() for vuln in ["admin", "wp-", "phpmyadmin"]):
                attack_type = "admin_access_attempt"
            elif any(payload in str(request.url).lower() for payload in ["<script>", "union select", "' or 1=1"]):
                attack_type = "injection_attempt"
            elif "/.." in full_path or "%2e%2e" in full_path:
                attack_type = "directory_traversal"
            
            await self.log_attack(
                request.client.host,
                request.client.port,
                payload=str(request.url),
                attack_type=attack_type,
                user_agent=request.headers.get("user-agent", "unknown")
            )
            
            # Return appropriate fake response
            if full_path in self.fake_pages:
                return HTMLResponse(self.fake_pages[full_path])
            elif any(vuln in full_path.lower() for vuln in self.vulnerable_endpoints):
                return HTMLResponse(self._generate_vulnerable_page(full_path))
            else:
                # Use LLM to generate realistic 404 page
                context = {
                    "service": "http",
                    "path": full_path,
                    "user_agent": request.headers.get("user-agent", "unknown")
                }
                
                llm_response = await llm_service.generate_response(
                    f"Generate a realistic HTTP 404 error page for path: {full_path}",
                    context
                )
                
                return HTMLResponse(
                    f"<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>{llm_response}</p></body></html>",
                    status_code=404
                )
    
    async def start(self):
        """Start HTTP honeypot"""
        try:
            import uvicorn
            
            def run_server():
                uvicorn.run(
                    self.app,
                    host="0.0.0.0",
                    port=self.port,
                    log_level="warning"
                )
            
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()
            
            logger.info(f"HTTP Honeypot listening on port {self.port}")
            
            # Keep the coroutine running
            while self.server_thread.is_alive():
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Error starting HTTP honeypot: {e}")
    
    async def stop(self):
        """Stop HTTP honeypot"""
        # Note: uvicorn doesn't have a clean way to stop from here
        # In production, you'd want to use a proper ASGI server with lifecycle management
        logger.info("HTTP Honeypot stop requested")
    
    def _generate_index_page(self) -> str:
        """Generate fake index page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Industrial Control System</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .content { padding: 20px; }
                .login-link { color: #3498db; text-decoration: none; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Industrial IoT Gateway</h1>
                <p>SCADA Control Panel v2.1</p>
            </div>
            <div class="content">
                <h2>Welcome to the Industrial Control System</h2>
                <p>This system controls critical infrastructure components.</p>
                <ul>
                    <li><a href="/admin" class="login-link">Admin Panel</a></li>
                    <li><a href="/dashboard" class="login-link">Dashboard</a></li>
                    <li><a href="/config" class="login-link">Configuration</a></li>
                </ul>
                <p><em>Authorized personnel only</em></p>
            </div>
        </body>
        </html>
        """
    
    def _generate_admin_page(self) -> str:
        """Generate fake admin page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - Industrial Control System</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .login-form { max-width: 300px; margin: 50px auto; padding: 20px; border: 1px solid #ddd; }
                input { width: 100%; padding: 10px; margin: 10px 0; }
                button { width: 100%; padding: 10px; background: #3498db; color: white; border: none; }
            </style>
        </head>
        <body>
            <div class="login-form">
                <h2>Admin Login</h2>
                <form method="post" action="/login">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Login</button>
                </form>
                <p><small>Default credentials: admin/admin</small></p>
            </div>
        </body>
        </html>
        """
    
    def _generate_login_page(self) -> str:
        """Generate fake login page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - Industrial Control System</title>
            <style>
                body { font-family: Arial, sans-serif; background: #ecf0f1; margin: 0; padding: 0; }
                .container { max-width: 400px; margin: 100px auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 3px; }
                button { width: 100%; padding: 12px; background: #e74c3c; color: white; border: none; border-radius: 3px; cursor: pointer; }
                .error { color: #e74c3c; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>System Login</h2>
                <div class="error">Invalid credentials. Please try again.</div>
                <form method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit">Access System</button>
                </form>
                <p><small>Industrial Control System v2.1.3</small></p>
            </div>
        </body>
        </html>
        """
    
    def _generate_dashboard_page(self) -> str:
        """Generate fake dashboard page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Industrial Control System</title>
        </head>
        <body>
            <h1>Access Denied</h1>
            <p>Please login to access the dashboard.</p>
            <a href="/login">Login</a>
        </body>
        </html>
        """
    
    def _generate_config_page(self) -> str:
        """Generate fake config page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Configuration - Industrial Control System</title>
        </head>
        <body>
            <h1>System Configuration</h1>
            <p>Unauthorized access detected. This incident will be reported.</p>
        </body>
        </html>
        """
    
    def _generate_users_api(self) -> dict:
        """Generate fake users API response"""
        return {
            "users": [
                {"id": 1, "username": "admin", "role": "administrator"},
                {"id": 2, "username": "operator", "role": "operator"},
                {"id": 3, "username": "engineer", "role": "engineer"}
            ],
            "total": 3
        }
    
    def _generate_phpmyadmin_page(self) -> str:
        """Generate fake phpMyAdmin page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>phpMyAdmin</title>
        </head>
        <body>
            <h1>phpMyAdmin 4.9.0.1</h1>
            <p>MySQL Database Administration</p>
            <form>
                <input type="text" placeholder="Username">
                <input type="password" placeholder="Password">
                <button>Login</button>
            </form>
        </body>
        </html>
        """
    
    def _generate_wordpress_admin(self) -> str:
        """Generate fake WordPress admin page"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>WordPress Admin</title>
        </head>
        <body>
            <h1>WordPress Administration</h1>
            <p>Please login to continue.</p>
        </body>
        </html>
        """
    
    def _generate_vulnerable_page(self, path: str) -> str:
        """Generate response for vulnerable endpoints"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>System Access</title>
        </head>
        <body>
            <h1>Restricted Area</h1>
            <p>You are trying to access: {path}</p>
            <p>This area requires special authorization.</p>
            <p>Contact system administrator for access.</p>
        </body>
        </html>
        """