"""
Modbus protocol handler for the honeypot.
"""

import asyncio
import logging
import struct
from typing import Dict, Any, Optional


class ModbusHandler:
    """Modbus TCP protocol handler."""
    
    def __init__(self, config, attack_detector, response_engine, logger_manager):
        self.config = config
        self.attack_detector = attack_detector
        self.response_engine = response_engine
        self.logger_manager = logger_manager
        self.logger = logging.getLogger('honeypot.modbus')
        
        # Simulated Modbus data
        self.coils = [False] * 65536  # Discrete outputs
        self.discrete_inputs = [False] * 65536  # Discrete inputs
        self.holding_registers = [0] * 65536  # 16-bit read/write registers
        self.input_registers = [0] * 65536  # 16-bit read-only registers
        
        # Initialize some realistic industrial data
        self._initialize_industrial_data()
        
    def _initialize_industrial_data(self) -> None:
        """Initialize realistic industrial data."""
        # Temperature sensors (registers 0-10)
        self.input_registers[0:11] = [235, 240, 238, 242, 236, 239, 241, 237, 243, 234, 245]  # 23.5°C - 24.5°C * 10
        
        # Pressure sensors (registers 20-25)  
        self.input_registers[20:26] = [1013, 1015, 1012, 1014, 1016, 1011]  # ~101.3 kPa * 10
        
        # Flow rates (registers 30-35)
        self.input_registers[30:36] = [1257, 1245, 1268, 1234, 1276, 1229]  # ~125 L/min * 10
        
        # Pump status (coils 0-9)
        self.coils[0:10] = [True, True, False, True, True, False, True, False, True, True]
        
        # Valve positions (holding registers 100-109) - 0-100% open
        self.holding_registers[100:110] = [45, 67, 23, 89, 12, 78, 56, 34, 91, 5]
        
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming Modbus connection."""
        client_info = writer.get_extra_info('peername')
        source_ip = client_info[0] if client_info else 'unknown'
        
        try:
            # Log connection
            self.logger_manager.log_connection({
                'source_ip': source_ip,
                'target_port': 502,
                'protocol': 'Modbus',
                'status': 'established'
            })
            
            # Handle Modbus requests
            while True:
                try:
                    # Read Modbus request
                    request = await asyncio.wait_for(reader.read(1024), timeout=30.0)
                    if not request:
                        break
                        
                    # Process Modbus request
                    response = await self._process_modbus_request(request, source_ip)
                    
                    if response:
                        writer.write(response)
                        await writer.drain()
                        
                except asyncio.TimeoutError:
                    break
                except Exception as e:
                    self.logger.error(f"Error processing Modbus request: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error handling Modbus connection from {source_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
                
    async def _process_modbus_request(self, request: bytes, source_ip: str) -> Optional[bytes]:
        """Process Modbus TCP request."""
        if len(request) < 8:  # Minimum Modbus TCP frame size
            return None
            
        try:
            # Parse Modbus TCP header
            transaction_id = struct.unpack('>H', request[0:2])[0]
            protocol_id = struct.unpack('>H', request[2:4])[0]
            length = struct.unpack('>H', request[4:6])[0]
            unit_id = request[6]
            
            if protocol_id != 0:  # Must be 0 for Modbus TCP
                return None
                
            # Parse Modbus PDU
            if len(request) < 8:
                return None
                
            function_code = request[7]
            
            # Analyze for attacks
            attack_info = await self._analyze_modbus_request(request, source_ip)
            
            if attack_info:
                # Handle potential attack
                response_data = await self.response_engine.generate_response(attack_info)
                return self._create_error_response(transaction_id, unit_id, function_code, 0x01)  # Illegal function
            else:
                # Process legitimate request
                return self._process_function_code(transaction_id, unit_id, function_code, request[8:])
                
        except Exception as e:
            self.logger.error(f"Error parsing Modbus request: {e}")
            return None
            
    def _process_function_code(self, transaction_id: int, unit_id: int, function_code: int, data: bytes) -> Optional[bytes]:
        """Process Modbus function code."""
        try:
            if function_code == 0x01:  # Read Coils
                return self._read_coils(transaction_id, unit_id, data)
            elif function_code == 0x02:  # Read Discrete Inputs
                return self._read_discrete_inputs(transaction_id, unit_id, data)
            elif function_code == 0x03:  # Read Holding Registers
                return self._read_holding_registers(transaction_id, unit_id, data)
            elif function_code == 0x04:  # Read Input Registers
                return self._read_input_registers(transaction_id, unit_id, data)
            elif function_code == 0x05:  # Write Single Coil
                return self._write_single_coil(transaction_id, unit_id, data)
            elif function_code == 0x06:  # Write Single Register
                return self._write_single_register(transaction_id, unit_id, data)
            elif function_code == 0x0F:  # Write Multiple Coils
                return self._write_multiple_coils(transaction_id, unit_id, data)
            elif function_code == 0x10:  # Write Multiple Registers
                return self._write_multiple_registers(transaction_id, unit_id, data)
            else:
                # Unsupported function code
                return self._create_error_response(transaction_id, unit_id, function_code, 0x01)
                
        except Exception as e:
            self.logger.error(f"Error processing function code {function_code}: {e}")
            return self._create_error_response(transaction_id, unit_id, function_code, 0x04)  # Server device failure
            
    def _read_coils(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Read coils (function code 0x01)."""
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x01, 0x03)
            
        start_address = struct.unpack('>H', data[0:2])[0]
        quantity = struct.unpack('>H', data[2:4])[0]
        
        if quantity < 1 or quantity > 2000 or start_address + quantity > len(self.coils):
            return self._create_error_response(transaction_id, unit_id, 0x01, 0x02)
            
        # Pack coils into bytes
        byte_count = (quantity + 7) // 8
        coil_bytes = bytearray(byte_count)
        
        for i in range(quantity):
            if self.coils[start_address + i]:
                byte_index = i // 8
                bit_index = i % 8
                coil_bytes[byte_index] |= (1 << bit_index)
                
        # Create response
        response_data = struct.pack('B', byte_count) + coil_bytes
        return self._create_response(transaction_id, unit_id, 0x01, response_data)
        
    def _read_discrete_inputs(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Read discrete inputs (function code 0x02)."""
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x02, 0x03)
            
        start_address = struct.unpack('>H', data[0:2])[0]
        quantity = struct.unpack('>H', data[2:4])[0]
        
        if quantity < 1 or quantity > 2000 or start_address + quantity > len(self.discrete_inputs):
            return self._create_error_response(transaction_id, unit_id, 0x02, 0x02)
            
        # Pack inputs into bytes (similar to coils)
        byte_count = (quantity + 7) // 8
        input_bytes = bytearray(byte_count)
        
        for i in range(quantity):
            if self.discrete_inputs[start_address + i]:
                byte_index = i // 8
                bit_index = i % 8
                input_bytes[byte_index] |= (1 << bit_index)
                
        response_data = struct.pack('B', byte_count) + input_bytes
        return self._create_response(transaction_id, unit_id, 0x02, response_data)
        
    def _read_holding_registers(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Read holding registers (function code 0x03)."""
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x03, 0x03)
            
        start_address = struct.unpack('>H', data[0:2])[0]
        quantity = struct.unpack('>H', data[2:4])[0]
        
        if quantity < 1 or quantity > 125 or start_address + quantity > len(self.holding_registers):
            return self._create_error_response(transaction_id, unit_id, 0x03, 0x02)
            
        # Pack registers
        byte_count = quantity * 2
        register_data = bytearray()
        
        for i in range(quantity):
            register_value = self.holding_registers[start_address + i]
            register_data.extend(struct.pack('>H', register_value))
            
        response_data = struct.pack('B', byte_count) + register_data
        return self._create_response(transaction_id, unit_id, 0x03, response_data)
        
    def _read_input_registers(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Read input registers (function code 0x04)."""
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x04, 0x03)
            
        start_address = struct.unpack('>H', data[0:2])[0]
        quantity = struct.unpack('>H', data[2:4])[0]
        
        if quantity < 1 or quantity > 125 or start_address + quantity > len(self.input_registers):
            return self._create_error_response(transaction_id, unit_id, 0x04, 0x02)
            
        # Pack registers
        byte_count = quantity * 2
        register_data = bytearray()
        
        for i in range(quantity):
            register_value = self.input_registers[start_address + i]
            register_data.extend(struct.pack('>H', register_value))
            
        response_data = struct.pack('B', byte_count) + register_data
        return self._create_response(transaction_id, unit_id, 0x04, response_data)
        
    def _write_single_coil(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Write single coil (function code 0x05)."""
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x05, 0x03)
            
        address = struct.unpack('>H', data[0:2])[0]
        value = struct.unpack('>H', data[2:4])[0]
        
        if address >= len(self.coils):
            return self._create_error_response(transaction_id, unit_id, 0x05, 0x02)
            
        if value == 0xFF00:
            self.coils[address] = True
        elif value == 0x0000:
            self.coils[address] = False
        else:
            return self._create_error_response(transaction_id, unit_id, 0x05, 0x03)
            
        # Echo back the request data
        return self._create_response(transaction_id, unit_id, 0x05, data)
        
    def _write_single_register(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Write single register (function code 0x06)."""
        if len(data) < 4:
            return self._create_error_response(transaction_id, unit_id, 0x06, 0x03)
            
        address = struct.unpack('>H', data[0:2])[0]
        value = struct.unpack('>H', data[2:4])[0]
        
        if address >= len(self.holding_registers):
            return self._create_error_response(transaction_id, unit_id, 0x06, 0x02)
            
        self.holding_registers[address] = value
        
        # Echo back the request data
        return self._create_response(transaction_id, unit_id, 0x06, data)
        
    def _write_multiple_coils(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Write multiple coils (function code 0x0F)."""
        if len(data) < 5:
            return self._create_error_response(transaction_id, unit_id, 0x0F, 0x03)
            
        start_address = struct.unpack('>H', data[0:2])[0]
        quantity = struct.unpack('>H', data[2:4])[0]
        byte_count = data[4]
        
        if quantity < 1 or quantity > 1968 or start_address + quantity > len(self.coils):
            return self._create_error_response(transaction_id, unit_id, 0x0F, 0x02)
            
        if len(data) < 5 + byte_count:
            return self._create_error_response(transaction_id, unit_id, 0x0F, 0x03)
            
        # Set coils
        coil_data = data[5:5+byte_count]
        for i in range(quantity):
            byte_index = i // 8
            bit_index = i % 8
            if byte_index < len(coil_data):
                self.coils[start_address + i] = bool(coil_data[byte_index] & (1 << bit_index))
                
        # Response contains start address and quantity
        response_data = struct.pack('>HH', start_address, quantity)
        return self._create_response(transaction_id, unit_id, 0x0F, response_data)
        
    def _write_multiple_registers(self, transaction_id: int, unit_id: int, data: bytes) -> bytes:
        """Write multiple registers (function code 0x10)."""
        if len(data) < 5:
            return self._create_error_response(transaction_id, unit_id, 0x10, 0x03)
            
        start_address = struct.unpack('>H', data[0:2])[0]
        quantity = struct.unpack('>H', data[2:4])[0]
        byte_count = data[4]
        
        if quantity < 1 or quantity > 123 or start_address + quantity > len(self.holding_registers):
            return self._create_error_response(transaction_id, unit_id, 0x10, 0x02)
            
        if len(data) < 5 + byte_count or byte_count != quantity * 2:
            return self._create_error_response(transaction_id, unit_id, 0x10, 0x03)
            
        # Set registers
        for i in range(quantity):
            register_data = data[5 + i*2:5 + i*2 + 2]
            self.holding_registers[start_address + i] = struct.unpack('>H', register_data)[0]
            
        # Response contains start address and quantity
        response_data = struct.pack('>HH', start_address, quantity)
        return self._create_response(transaction_id, unit_id, 0x10, response_data)
        
    def _create_response(self, transaction_id: int, unit_id: int, function_code: int, data: bytes) -> bytes:
        """Create Modbus TCP response."""
        # Modbus TCP header
        protocol_id = 0
        length = 2 + len(data)  # Unit ID + Function Code + Data
        
        header = struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id)
        pdu = struct.pack('B', function_code) + data
        
        return header + pdu
        
    def _create_error_response(self, transaction_id: int, unit_id: int, function_code: int, exception_code: int) -> bytes:
        """Create Modbus error response."""
        error_function_code = function_code | 0x80
        data = struct.pack('B', exception_code)
        
        return self._create_response(transaction_id, unit_id, error_function_code, data)
        
    async def _analyze_modbus_request(self, request: bytes, source_ip: str) -> Optional[Dict[str, Any]]:
        """Analyze Modbus request for attacks."""
        # Convert request to hex string for analysis
        hex_payload = request.hex()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            # Attempts to read/write large ranges
            len(request) > 260,  # Unusually large request
            # Function codes that shouldn't be used normally
            b'\x08' in request,  # Diagnostics
            b'\x0B' in request,  # Get Comm Event Counter
            b'\x0C' in request,  # Get Comm Event Log
            b'\x11' in request,  # Report Slave ID
            b'\x16' in request,  # Mask Write Register
            b'\x17' in request,  # Read/Write Multiple Registers
        ]
        
        if any(suspicious_patterns):
            analysis_data = {
                'source_ip': source_ip,
                'target_port': 502,
                'protocol': 'Modbus',
                'payload': hex_payload,
                'context': 'Modbus industrial protocol',
                'system_type': 'PLC'
            }
            
            return await self.attack_detector.analyze_request(analysis_data)
            
        return None