from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List
from src.database.models import get_db, AttackLog, HoneypotSession, SystemMetrics
from src.monitoring.metrics import metrics_collector
from src.core.honeypot import honeypot_manager
from loguru import logger


class WebInterface:
    """Web interface for honeypot management and monitoring"""
    
    def __init__(self):
        self.app = FastAPI(title="Industrial IoT Honeypot", version="1.0.0")
        self.setup_routes()
        
        # In a real deployment, you'd have separate static files
        # For now, we'll serve everything from the API
    
    def setup_routes(self):
        """Setup web interface routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Main dashboard"""
            return HTMLResponse(self._generate_dashboard_html())
        
        @self.app.get("/api/status")
        async def get_status():
            """Get system status"""
            return {
                "status": "running",
                "honeypots": honeypot_manager.get_status(),
                "metrics": metrics_collector.get_service_status(),
                "timestamp": datetime.now().isoformat()
            }
        
        @self.app.get("/api/attacks/summary")
        async def get_attack_summary(hours: int = 24):
            """Get attack summary"""
            return metrics_collector.get_attack_summary(hours)
        
        @self.app.get("/api/attacks/recent")
        async def get_recent_attacks(limit: int = 50):
            """Get recent attacks"""
            return metrics_collector.get_recent_attacks(limit)
        
        @self.app.get("/api/attacks/geographic")
        async def get_geographic_distribution():
            """Get geographic distribution of attacks"""
            return metrics_collector.get_geographic_distribution()
        
        @self.app.get("/api/metrics/system")
        async def get_system_metrics(db: Session = Depends(get_db)):
            """Get system metrics"""
            try:
                # Get metrics from the last hour
                since = datetime.now() - timedelta(hours=1)
                metrics = db.query(SystemMetrics).filter(
                    SystemMetrics.timestamp >= since
                ).order_by(SystemMetrics.timestamp.desc()).limit(60).all()
                
                result = []
                for metric in reversed(metrics):
                    result.append({
                        "timestamp": metric.timestamp.isoformat(),
                        "cpu_usage": metric.cpu_usage,
                        "memory_usage": metric.memory_usage,
                        "disk_usage": metric.disk_usage,
                        "active_connections": metric.active_connections,
                        "attack_rate": metric.attack_rate
                    })
                
                return result
            except Exception as e:
                logger.error(f"Error getting system metrics: {e}")
                return []
        
        @self.app.get("/api/sessions/active")
        async def get_active_sessions(db: Session = Depends(get_db)):
            """Get active sessions"""
            try:
                sessions = db.query(HoneypotSession).filter(
                    HoneypotSession.is_active == True
                ).all()
                
                result = []
                for session in sessions:
                    result.append({
                        "session_id": session.session_id,
                        "source_ip": session.source_ip,
                        "service": session.service,
                        "start_time": session.start_time.isoformat(),
                        "duration": (datetime.now() - session.start_time).total_seconds(),
                        "commands_count": session.commands_count
                    })
                
                return result
            except Exception as e:
                logger.error(f"Error getting active sessions: {e}")
                return []
        
        @self.app.get("/api/attacks/{attack_id}")
        async def get_attack_details(attack_id: int, db: Session = Depends(get_db)):
            """Get detailed attack information"""
            try:
                attack = db.query(AttackLog).filter(AttackLog.id == attack_id).first()
                if not attack:
                    raise HTTPException(status_code=404, detail="Attack not found")
                
                return {
                    "id": attack.id,
                    "timestamp": attack.timestamp.isoformat(),
                    "source_ip": attack.source_ip,
                    "source_port": attack.source_port,
                    "destination_port": attack.destination_port,
                    "protocol": attack.protocol,
                    "service": attack.service,
                    "attack_type": attack.attack_type,
                    "payload": attack.payload,
                    "user_agent": attack.user_agent,
                    "country": attack.country,
                    "city": attack.city,
                    "latitude": attack.latitude,
                    "longitude": attack.longitude,
                    "severity": attack.severity,
                    "confidence_score": attack.confidence_score,
                    "llm_analysis": attack.llm_analysis,
                    "session_id": attack.session_id,
                    "commands_executed": attack.commands_executed,
                    "files_accessed": attack.files_accessed,
                    "response_generated": attack.response_generated
                }
            except Exception as e:
                logger.error(f"Error getting attack details: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.post("/api/honeypots/{service}/toggle")
        async def toggle_honeypot(service: str):
            """Toggle honeypot service on/off"""
            # This would need to be implemented based on your service management
            return {"message": f"Honeypot {service} toggled"}
        
        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard_page(request: Request):
            """Dashboard page"""
            return HTMLResponse(self._generate_dashboard_html())
        
        @self.app.get("/attacks", response_class=HTMLResponse)
        async def attacks_page(request: Request):
            """Attacks page"""
            return HTMLResponse(self._generate_attacks_html())
        
        @self.app.get("/analytics", response_class=HTMLResponse)
        async def analytics_page(request: Request):
            """Analytics page"""
            return HTMLResponse(self._generate_analytics_html())
    
    def _generate_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Industrial IoT Honeypot Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
                .header { background: #2c3e50; color: white; padding: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .header h1 { display: inline-block; }
                .nav { float: right; }
                .nav a { color: white; text-decoration: none; margin-left: 2rem; padding: 0.5rem 1rem; border-radius: 4px; }
                .nav a:hover { background: #34495e; }
                .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
                .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
                .card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .card h3 { margin-bottom: 1rem; color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 0.5rem; }
                .metric { display: flex; justify-content: space-between; align-items: center; margin: 0.5rem 0; }
                .metric-value { font-weight: bold; color: #e74c3c; }
                .status-indicator { width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 0.5rem; }
                .status-running { background: #27ae60; }
                .status-stopped { background: #e74c3c; }
                .alert { background: #f8d7da; color: #721c24; padding: 1rem; border-radius: 4px; margin: 1rem 0; border-left: 4px solid #f5c6cb; }
                .btn { background: #3498db; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
                .btn:hover { background: #2980b9; }
                .chart-container { height: 300px; margin-top: 1rem; }
                table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
                th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
                th { background: #f8f9fa; font-weight: 600; }
                .severity-high { color: #e74c3c; font-weight: bold; }
                .severity-medium { color: #f39c12; font-weight: bold; }
                .severity-low { color: #27ae60; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🍯 Industrial IoT Honeypot</h1>
                <nav class="nav">
                    <a href="/">Dashboard</a>
                    <a href="/attacks">Attacks</a>
                    <a href="/analytics">Analytics</a>
                </nav>
                <div style="clear: both;"></div>
            </div>
            
            <div class="container">
                <div id="status-alert" class="alert" style="display: none;"></div>
                
                <div class="grid">
                    <div class="card">
                        <h3>System Status</h3>
                        <div id="system-status">
                            <div class="metric">
                                <span>System</span>
                                <span><span class="status-indicator status-running"></span>Running</span>
                            </div>
                            <div class="metric">
                                <span>CPU Usage</span>
                                <span class="metric-value" id="cpu-usage">Loading...</span>
                            </div>
                            <div class="metric">
                                <span>Memory Usage</span>
                                <span class="metric-value" id="memory-usage">Loading...</span>
                            </div>
                            <div class="metric">
                                <span>Active Connections</span>
                                <span class="metric-value" id="active-connections">Loading...</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>Honeypot Services</h3>
                        <div id="honeypot-services">Loading...</div>
                    </div>
                    
                    <div class="card">
                        <h3>Attack Summary (24h)</h3>
                        <div id="attack-summary">
                            <div class="metric">
                                <span>Total Attacks</span>
                                <span class="metric-value" id="total-attacks">Loading...</span>
                            </div>
                            <div class="metric">
                                <span>Unique IPs</span>
                                <span class="metric-value" id="unique-ips">Loading...</span>
                            </div>
                            <div class="metric">
                                <span>Top Service</span>
                                <span class="metric-value" id="top-service">Loading...</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="grid">
                    <div class="card">
                        <h3>System Metrics</h3>
                        <div class="chart-container">
                            <canvas id="systemChart"></canvas>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h3>Attack Distribution</h3>
                        <div class="chart-container">
                            <canvas id="attackChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <h3>Recent Attacks</h3>
                    <table id="recent-attacks-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Source IP</th>
                                <th>Service</th>
                                <th>Attack Type</th>
                                <th>Severity</th>
                                <th>Country</th>
                            </tr>
                        </thead>
                        <tbody id="recent-attacks">
                            <tr><td colspan="6">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <script>
                // Dashboard JavaScript
                let systemChart, attackChart;
                
                async function fetchData(url) {
                    try {
                        const response = await fetch(url);
                        return await response.json();
                    } catch (error) {
                        console.error('Error fetching data:', error);
                        return null;
                    }
                }
                
                async function updateDashboard() {
                    // Update system status
                    const status = await fetchData('/api/status');
                    if (status) {
                        updateSystemStatus(status);
                        updateHoneypotServices(status.honeypots);
                    }
                    
                    // Update attack summary
                    const summary = await fetchData('/api/attacks/summary');
                    if (summary) {
                        updateAttackSummary(summary);
                    }
                    
                    // Update recent attacks
                    const recentAttacks = await fetchData('/api/attacks/recent?limit=10');
                    if (recentAttacks) {
                        updateRecentAttacks(recentAttacks);
                    }
                    
                    // Update charts
                    await updateCharts();
                }
                
                function updateSystemStatus(status) {
                    // This would be updated with real system metrics
                    document.getElementById('cpu-usage').textContent = 'N/A';
                    document.getElementById('memory-usage').textContent = 'N/A';
                    document.getElementById('active-connections').textContent = '0';
                }
                
                function updateHoneypotServices(honeypots) {
                    const container = document.getElementById('honeypot-services');
                    let html = '';
                    
                    if (honeypots && honeypots.services) {
                        for (const [name, service] of Object.entries(honeypots.services)) {
                            const statusClass = service.enabled ? 'status-running' : 'status-stopped';
                            const statusText = service.enabled ? 'Running' : 'Stopped';
                            
                            html += `
                                <div class="metric">
                                    <span>${name.toUpperCase()} (${service.port})</span>
                                    <span><span class="status-indicator ${statusClass}"></span>${statusText}</span>
                                </div>
                            `;
                        }
                    } else {
                        html = '<div class="metric"><span>No services configured</span></div>';
                    }
                    
                    container.innerHTML = html;
                }
                
                function updateAttackSummary(summary) {
                    document.getElementById('total-attacks').textContent = summary.total_attacks || 0;
                    document.getElementById('unique-ips').textContent = summary.unique_ips || 0;
                    
                    // Find top service
                    let topService = 'None';
                    if (summary.services) {
                        const services = Object.entries(summary.services);
                        if (services.length > 0) {
                            topService = services.sort((a, b) => b[1] - a[1])[0][0];
                        }
                    }
                    document.getElementById('top-service').textContent = topService;
                }
                
                function updateRecentAttacks(attacks) {
                    const tbody = document.getElementById('recent-attacks');
                    
                    if (attacks.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6">No recent attacks</td></tr>';
                        return;
                    }
                    
                    let html = '';
                    attacks.forEach(attack => {
                        const time = new Date(attack.timestamp).toLocaleTimeString();
                        const severityClass = `severity-${attack.severity || 'medium'}`;
                        
                        html += `
                            <tr>
                                <td>${time}</td>
                                <td>${attack.source_ip}</td>
                                <td>${attack.service}</td>
                                <td>${attack.attack_type}</td>
                                <td class="${severityClass}">${attack.severity || 'medium'}</td>
                                <td>${attack.country || 'Unknown'}</td>
                            </tr>
                        `;
                    });
                    
                    tbody.innerHTML = html;
                }
                
                async function updateCharts() {
                    // Update system metrics chart
                    const systemMetrics = await fetchData('/api/metrics/system');
                    if (systemMetrics && systemChart) {
                        updateSystemChart(systemMetrics);
                    }
                    
                    // Update attack distribution chart
                    const summary = await fetchData('/api/attacks/summary');
                    if (summary && attackChart) {
                        updateAttackChart(summary);
                    }
                }
                
                function initCharts() {
                    // System metrics chart
                    const systemCtx = document.getElementById('systemChart').getContext('2d');
                    systemChart = new Chart(systemCtx, {
                        type: 'line',
                        data: {
                            labels: [],
                            datasets: [{
                                label: 'CPU %',
                                data: [],
                                borderColor: '#e74c3c',
                                tension: 0.1
                            }, {
                                label: 'Memory %',
                                data: [],
                                borderColor: '#3498db',
                                tension: 0.1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: { beginAtZero: true, max: 100 }
                            }
                        }
                    });
                    
                    // Attack distribution chart
                    const attackCtx = document.getElementById('attackChart').getContext('2d');
                    attackChart = new Chart(attackCtx, {
                        type: 'doughnut',
                        data: {
                            labels: [],
                            datasets: [{
                                data: [],
                                backgroundColor: ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6']
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false
                        }
                    });
                }
                
                function updateSystemChart(metrics) {
                    if (metrics.length > 0) {
                        systemChart.data.labels = metrics.map(m => new Date(m.timestamp).toLocaleTimeString());
                        systemChart.data.datasets[0].data = metrics.map(m => m.cpu_usage);
                        systemChart.data.datasets[1].data = metrics.map(m => m.memory_usage);
                        systemChart.update();
                    }
                }
                
                function updateAttackChart(summary) {
                    if (summary.services) {
                        attackChart.data.labels = Object.keys(summary.services);
                        attackChart.data.datasets[0].data = Object.values(summary.services);
                        attackChart.update();
                    }
                }
                
                // Initialize dashboard
                document.addEventListener('DOMContentLoaded', function() {
                    initCharts();
                    updateDashboard();
                    
                    // Update every 30 seconds
                    setInterval(updateDashboard, 30000);
                });
            </script>
        </body>
        </html>
        """
    
    def _generate_attacks_html(self) -> str:
        """Generate attacks page HTML"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Attack Analysis - Industrial IoT Honeypot</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 1rem; margin: -20px -20px 20px -20px; }
                .filter-panel { background: #f8f9fa; padding: 1rem; border-radius: 5px; margin-bottom: 20px; }
                .attack-item { background: white; border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
                .attack-header { display: flex; justify-content: space-between; align-items: center; }
                .severity-high { border-left: 4px solid #e74c3c; }
                .severity-medium { border-left: 4px solid #f39c12; }
                .severity-low { border-left: 4px solid #27ae60; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Attack Analysis</h1>
                <a href="/" style="color: white;">← Back to Dashboard</a>
            </div>
            
            <div class="filter-panel">
                <h3>Filters</h3>
                <select id="service-filter">
                    <option value="">All Services</option>
                    <option value="ssh">SSH</option>
                    <option value="http">HTTP</option>
                    <option value="modbus">Modbus</option>
                </select>
                
                <select id="severity-filter">
                    <option value="">All Severities</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                
                <button onclick="filterAttacks()">Apply Filters</button>
            </div>
            
            <div id="attacks-container">
                Loading attacks...
            </div>
            
            <script>
                async function loadAttacks() {
                    try {
                        const response = await fetch('/api/attacks/recent?limit=100');
                        const attacks = await response.json();
                        displayAttacks(attacks);
                    } catch (error) {
                        console.error('Error loading attacks:', error);
                    }
                }
                
                function displayAttacks(attacks) {
                    const container = document.getElementById('attacks-container');
                    
                    if (attacks.length === 0) {
                        container.innerHTML = '<p>No attacks found.</p>';
                        return;
                    }
                    
                    let html = '';
                    attacks.forEach(attack => {
                        const time = new Date(attack.timestamp).toLocaleString();
                        const severityClass = `severity-${attack.severity || 'medium'}`;
                        
                        html += `
                            <div class="attack-item ${severityClass}">
                                <div class="attack-header">
                                    <strong>${attack.source_ip} → ${attack.service.toUpperCase()}</strong>
                                    <span>${time}</span>
                                </div>
                                <p><strong>Attack Type:</strong> ${attack.attack_type}</p>
                                <p><strong>Severity:</strong> ${attack.severity || 'medium'}</p>
                                ${attack.payload ? `<p><strong>Payload:</strong> <code>${attack.payload}</code></p>` : ''}
                                <p><strong>Country:</strong> ${attack.country || 'Unknown'}</p>
                            </div>
                        `;
                    });
                    
                    container.innerHTML = html;
                }
                
                function filterAttacks() {
                    // Implement filtering logic
                    loadAttacks();
                }
                
                // Load attacks on page load
                loadAttacks();
            </script>
        </body>
        </html>
        """
    
    def _generate_analytics_html(self) -> str:
        """Generate analytics page HTML"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Analytics - Industrial IoT Honeypot</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background: #2c3e50; color: white; padding: 1rem; margin: -20px -20px 20px -20px; }
                .chart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                .chart-container { background: white; padding: 20px; border-radius: 5px; border: 1px solid #ddd; }
                .chart-container h3 { margin-top: 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 Security Analytics</h1>
                <a href="/" style="color: white;">← Back to Dashboard</a>
            </div>
            
            <div class="chart-grid">
                <div class="chart-container">
                    <h3>Attack Types Distribution</h3>
                    <canvas id="attackTypesChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Geographic Distribution</h3>
                    <canvas id="geoChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Hourly Attack Pattern</h3>
                    <canvas id="hourlyChart"></canvas>
                </div>
                
                <div class="chart-container">
                    <h3>Service Targets</h3>
                    <canvas id="servicesChart"></canvas>
                </div>
            </div>
            
            <script>
                // Initialize analytics charts
                document.addEventListener('DOMContentLoaded', function() {
                    loadAnalytics();
                });
                
                async function loadAnalytics() {
                    try {
                        const [summary, geo] = await Promise.all([
                            fetch('/api/attacks/summary').then(r => r.json()),
                            fetch('/api/attacks/geographic').then(r => r.json())
                        ]);
                        
                        createCharts(summary, geo);
                    } catch (error) {
                        console.error('Error loading analytics:', error);
                    }
                }
                
                function createCharts(summary, geo) {
                    // Attack types chart
                    if (summary.attack_types) {
                        new Chart(document.getElementById('attackTypesChart'), {
                            type: 'pie',
                            data: {
                                labels: Object.keys(summary.attack_types),
                                datasets: [{
                                    data: Object.values(summary.attack_types),
                                    backgroundColor: ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6']
                                }]
                            }
                        });
                    }
                    
                    // Geographic chart
                    if (geo && Object.keys(geo).length > 0) {
                        new Chart(document.getElementById('geoChart'), {
                            type: 'bar',
                            data: {
                                labels: Object.keys(geo),
                                datasets: [{
                                    label: 'Attacks by Country',
                                    data: Object.values(geo),
                                    backgroundColor: '#3498db'
                                }]
                            }
                        });
                    }
                    
                    // Hourly pattern chart
                    if (summary.hourly_distribution) {
                        const hours = Array.from({length: 24}, (_, i) => i);
                        const data = hours.map(h => summary.hourly_distribution[h] || 0);
                        
                        new Chart(document.getElementById('hourlyChart'), {
                            type: 'line',
                            data: {
                                labels: hours.map(h => h + ':00'),
                                datasets: [{
                                    label: 'Attacks per Hour',
                                    data: data,
                                    borderColor: '#e74c3c',
                                    tension: 0.1
                                }]
                            }
                        });
                    }
                    
                    // Services chart
                    if (summary.services) {
                        new Chart(document.getElementById('servicesChart'), {
                            type: 'doughnut',
                            data: {
                                labels: Object.keys(summary.services),
                                datasets: [{
                                    data: Object.values(summary.services),
                                    backgroundColor: ['#e74c3c', '#3498db', '#2ecc71', '#f39c12']
                                }]
                            }
                        });
                    }
                }
            </script>
        </body>
        </html>
        """


# Global web interface instance
web_interface = WebInterface()