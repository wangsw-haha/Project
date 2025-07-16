import asyncio
import socket
import struct
from typing import Dict, Any
from loguru import logger
from src.core.honeypot import BaseHoneypot
from src.llm.service import llm_service


class ModbusHoneypot(BaseHoneypot):
    """Modbus TCP Honeypot implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("modbus", config.get("port", 502), config)
        
        # Modbus registers simulation
        self.coils = [False] * 1000  # Discrete outputs
        self.discrete_inputs = [False] * 1000  # Discrete inputs
        self.holding_registers = [0] * 1000  # Analog outputs
        self.input_registers = [0] * 1000  # Analog inputs
        
        # Initialize some fake data
        self._initialize_fake_data()
        
        self.server_socket = None
    
    def _initialize_fake_data(self):
        """Initialize fake industrial data"""
        # Simulate temperature sensors (input registers)
        self.input_registers[0:10] = [250, 245, 260, 235, 280, 255, 270, 240, 265, 275]  # Temperature * 10
        
        # Simulate pressure sensors
        self.input_registers[10:20] = [1013, 1015, 1010, 1012, 1018, 1020, 1008, 1025, 1030, 1005]  # Pressure
        
        # Simulate motor status (coils)
        self.coils[0:5] = [True, False, True, False, True]  # Motors on/off
        
        # Simulate valve positions (holding registers)
        self.holding_registers[0:10] = [50, 75, 25, 100, 0, 80, 45, 90, 60, 35]  # Valve positions %
    
    async def start(self):
        """Start Modbus honeypot"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(10)
            self.server_socket.setblocking(False)
            
            logger.info(f"Modbus Honeypot listening on port {self.port}")
            
            while True:
                try:
                    client_socket, client_address = await asyncio.get_event_loop().sock_accept(self.server_socket)
                    asyncio.create_task(self._handle_client(client_socket, client_address))
                except Exception as e:
                    if self.server_socket:
                        logger.error(f"Error accepting Modbus connection: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error starting Modbus honeypot: {e}")
    
    async def stop(self):
        """Stop Modbus honeypot"""
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("Modbus Honeypot stopped")
    
    async def _handle_client(self, client_socket, client_address):
        """Handle Modbus client connection"""
        session_id = self.create_session(client_address[0])
        
        try:
            await self.log_attack(
                client_address[0],
                client_address[1],
                attack_type="modbus_connection",
                session_id=session_id
            )
            
            while True:
                try:
                    # Receive Modbus TCP frame
                    data = await asyncio.get_event_loop().sock_recv(client_socket, 1024)
                    if not data:
                        break
                    
                    response = await self._process_modbus_request(data, client_address[0], session_id)
                    if response:
                        await asyncio.get_event_loop().sock_sendall(client_socket, response)
                
                except Exception as e:
                    logger.error(f"Error handling Modbus client {client_address[0]}: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Error in Modbus session {session_id}: {e}")
        finally:
            client_socket.close()
            self.end_session(session_id)
    
    async def _process_modbus_request(self, data: bytes, source_ip: str, session_id: str) -> bytes:
        """Process Modbus TCP request"""
        try:
            if len(data) < 8:  # Minimum Modbus TCP frame size
                return None
            
            # Parse Modbus TCP header
            transaction_id = struct.unpack(">H", data[0:2])[0]
            protocol_id = struct.unpack(">H", data[2:4])[0]
            length = struct.unpack(">H", data[4:6])[0]
            unit_id = data[6]
            function_code = data[7]
            
            # Log the request
            await self.log_attack(
                source_ip,
                0,
                payload=f"Function: {function_code}, Unit: {unit_id}, Data: {data.hex()}",
                attack_type="modbus_request",
                session_id=session_id
            )
            
            # Process based on function code
            if function_code == 1:  # Read Coils
                return await self._read_coils(data, transaction_id, unit_id)
            elif function_code == 2:  # Read Discrete Inputs
                return await self._read_discrete_inputs(data, transaction_id, unit_id)
            elif function_code == 3:  # Read Holding Registers
                return await self._read_holding_registers(data, transaction_id, unit_id)
            elif function_code == 4:  # Read Input Registers
                return await self._read_input_registers(data, transaction_id, unit_id)
            elif function_code == 5:  # Write Single Coil
                return await self._write_single_coil(data, transaction_id, unit_id, source_ip, session_id)
            elif function_code == 6:  # Write Single Register
                return await self._write_single_register(data, transaction_id, unit_id, source_ip, session_id)
            elif function_code == 15:  # Write Multiple Coils
                return await self._write_multiple_coils(data, transaction_id, unit_id, source_ip, session_id)
            elif function_code == 16:  # Write Multiple Registers
                return await self._write_multiple_registers(data, transaction_id, unit_id, source_ip, session_id)
            else:
                # Unknown function code - return exception
                return self._create_exception_response(transaction_id, unit_id, function_code, 1)
        
        except Exception as e:
            logger.error(f"Error processing Modbus request: {e}")
            return None
    
    async def _read_coils(self, data: bytes, transaction_id: int, unit_id: int) -> bytes:
        """Handle Read Coils function (0x01)"""
        try:
            start_address = struct.unpack(">H", data[8:10])[0]
            quantity = struct.unpack(">H", data[10:12])[0]
            
            if quantity > 2000 or start_address + quantity > len(self.coils):
                return self._create_exception_response(transaction_id, unit_id, 1, 2)
            
            # Pack coils into bytes
            coil_bytes = []
            for i in range(0, quantity, 8):
                byte_val = 0
                for j in range(8):
                    if i + j < quantity and self.coils[start_address + i + j]:
                        byte_val |= (1 << j)
                coil_bytes.append(byte_val)
            
            response_data = bytes([len(coil_bytes)]) + bytes(coil_bytes)
            return self._create_response(transaction_id, unit_id, 1, response_data)
        
        except Exception as e:
            logger.error(f"Error reading coils: {e}")
            return self._create_exception_response(transaction_id, unit_id, 1, 4)
    
    async def _read_holding_registers(self, data: bytes, transaction_id: int, unit_id: int) -> bytes:
        """Handle Read Holding Registers function (0x03)"""
        try:
            start_address = struct.unpack(">H", data[8:10])[0]
            quantity = struct.unpack(">H", data[10:12])[0]
            
            if quantity > 125 or start_address + quantity > len(self.holding_registers):
                return self._create_exception_response(transaction_id, unit_id, 3, 2)
            
            response_data = bytes([quantity * 2])
            for i in range(quantity):
                reg_value = self.holding_registers[start_address + i]
                response_data += struct.pack(">H", reg_value)
            
            return self._create_response(transaction_id, unit_id, 3, response_data)
        
        except Exception as e:
            logger.error(f"Error reading holding registers: {e}")
            return self._create_exception_response(transaction_id, unit_id, 3, 4)
    
    async def _read_input_registers(self, data: bytes, transaction_id: int, unit_id: int) -> bytes:
        """Handle Read Input Registers function (0x04)"""
        try:
            start_address = struct.unpack(">H", data[8:10])[0]
            quantity = struct.unpack(">H", data[10:12])[0]
            
            if quantity > 125 or start_address + quantity > len(self.input_registers):
                return self._create_exception_response(transaction_id, unit_id, 4, 2)
            
            response_data = bytes([quantity * 2])
            for i in range(quantity):
                reg_value = self.input_registers[start_address + i]
                response_data += struct.pack(">H", reg_value)
            
            return self._create_response(transaction_id, unit_id, 4, response_data)
        
        except Exception as e:
            logger.error(f"Error reading input registers: {e}")
            return self._create_exception_response(transaction_id, unit_id, 4, 4)
    
    async def _write_single_coil(self, data: bytes, transaction_id: int, unit_id: int, 
                                source_ip: str, session_id: str) -> bytes:
        """Handle Write Single Coil function (0x05)"""
        try:
            address = struct.unpack(">H", data[8:10])[0]
            value = struct.unpack(">H", data[10:12])[0]
            
            if address >= len(self.coils):
                return self._create_exception_response(transaction_id, unit_id, 5, 2)
            
            # Log write operation (potential attack)
            await self.log_attack(
                source_ip,
                0,
                payload=f"Write coil {address} = {value}",
                attack_type="modbus_write",
                session_id=session_id
            )
            
            # Set coil value
            self.coils[address] = (value == 0xFF00)
            
            # Echo back the request
            response_data = data[8:12]
            return self._create_response(transaction_id, unit_id, 5, response_data)
        
        except Exception as e:
            logger.error(f"Error writing single coil: {e}")
            return self._create_exception_response(transaction_id, unit_id, 5, 4)
    
    async def _write_single_register(self, data: bytes, transaction_id: int, unit_id: int,
                                   source_ip: str, session_id: str) -> bytes:
        """Handle Write Single Register function (0x06)"""
        try:
            address = struct.unpack(">H", data[8:10])[0]
            value = struct.unpack(">H", data[10:12])[0]
            
            if address >= len(self.holding_registers):
                return self._create_exception_response(transaction_id, unit_id, 6, 2)
            
            # Log write operation (potential attack)
            await self.log_attack(
                source_ip,
                0,
                payload=f"Write register {address} = {value}",
                attack_type="modbus_write",
                session_id=session_id
            )
            
            # Set register value
            self.holding_registers[address] = value
            
            # Echo back the request
            response_data = data[8:12]
            return self._create_response(transaction_id, unit_id, 6, response_data)
        
        except Exception as e:
            logger.error(f"Error writing single register: {e}")
            return self._create_exception_response(transaction_id, unit_id, 6, 4)
    
    async def _write_multiple_coils(self, data: bytes, transaction_id: int, unit_id: int,
                                   source_ip: str, session_id: str) -> bytes:
        """Handle Write Multiple Coils function (0x0F)"""
        try:
            start_address = struct.unpack(">H", data[8:10])[0]
            quantity = struct.unpack(">H", data[10:12])[0]
            byte_count = data[12]
            
            if start_address + quantity > len(self.coils):
                return self._create_exception_response(transaction_id, unit_id, 15, 2)
            
            # Log write operation (potential attack)
            await self.log_attack(
                source_ip,
                0,
                payload=f"Write multiple coils {start_address}-{start_address + quantity - 1}",
                attack_type="modbus_write_multiple",
                session_id=session_id
            )
            
            # Extract and set coil values
            coil_data = data[13:13 + byte_count]
            for i in range(quantity):
                byte_index = i // 8
                bit_index = i % 8
                if byte_index < len(coil_data):
                    self.coils[start_address + i] = bool(coil_data[byte_index] & (1 << bit_index))
            
            # Response: echo start address and quantity
            response_data = struct.pack(">HH", start_address, quantity)
            return self._create_response(transaction_id, unit_id, 15, response_data)
        
        except Exception as e:
            logger.error(f"Error writing multiple coils: {e}")
            return self._create_exception_response(transaction_id, unit_id, 15, 4)
    
    async def _write_multiple_registers(self, data: bytes, transaction_id: int, unit_id: int,
                                       source_ip: str, session_id: str) -> bytes:
        """Handle Write Multiple Registers function (0x10)"""
        try:
            start_address = struct.unpack(">H", data[8:10])[0]
            quantity = struct.unpack(">H", data[10:12])[0]
            byte_count = data[12]
            
            if start_address + quantity > len(self.holding_registers):
                return self._create_exception_response(transaction_id, unit_id, 16, 2)
            
            # Log write operation (potential attack)
            await self.log_attack(
                source_ip,
                0,
                payload=f"Write multiple registers {start_address}-{start_address + quantity - 1}",
                attack_type="modbus_write_multiple",
                session_id=session_id
            )
            
            # Extract and set register values
            register_data = data[13:13 + byte_count]
            for i in range(quantity):
                reg_value = struct.unpack(">H", register_data[i*2:(i+1)*2])[0]
                self.holding_registers[start_address + i] = reg_value
            
            # Response: echo start address and quantity
            response_data = struct.pack(">HH", start_address, quantity)
            return self._create_response(transaction_id, unit_id, 16, response_data)
        
        except Exception as e:
            logger.error(f"Error writing multiple registers: {e}")
            return self._create_exception_response(transaction_id, unit_id, 16, 4)
    
    async def _read_discrete_inputs(self, data: bytes, transaction_id: int, unit_id: int) -> bytes:
        """Handle Read Discrete Inputs function (0x02)"""
        try:
            start_address = struct.unpack(">H", data[8:10])[0]
            quantity = struct.unpack(">H", data[10:12])[0]
            
            if quantity > 2000 or start_address + quantity > len(self.discrete_inputs):
                return self._create_exception_response(transaction_id, unit_id, 2, 2)
            
            # Pack discrete inputs into bytes
            input_bytes = []
            for i in range(0, quantity, 8):
                byte_val = 0
                for j in range(8):
                    if i + j < quantity and self.discrete_inputs[start_address + i + j]:
                        byte_val |= (1 << j)
                input_bytes.append(byte_val)
            
            response_data = bytes([len(input_bytes)]) + bytes(input_bytes)
            return self._create_response(transaction_id, unit_id, 2, response_data)
        
        except Exception as e:
            logger.error(f"Error reading discrete inputs: {e}")
            return self._create_exception_response(transaction_id, unit_id, 2, 4)
    
    def _create_response(self, transaction_id: int, unit_id: int, function_code: int, data: bytes) -> bytes:
        """Create Modbus TCP response"""
        length = len(data) + 2  # function code + data
        header = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
        return header + bytes([function_code]) + data
    
    def _create_exception_response(self, transaction_id: int, unit_id: int, function_code: int, exception_code: int) -> bytes:
        """Create Modbus exception response"""
        header = struct.pack(">HHHB", transaction_id, 0, 3, unit_id)
        return header + bytes([function_code | 0x80, exception_code])