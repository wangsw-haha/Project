#!/usr/bin/env python3
"""
Industrial Internet Honeypot with LLM-based Dynamic Response
Main entry point for the application.
"""

import asyncio
import argparse
import signal
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core import IndustrialHoneypot
from utils import Config


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Industrial Internet Honeypot with LLM-based Dynamic Response'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config/honeypot.yaml',
        help='Configuration file path (default: config/honeypot.yaml)'
    )
    
    parser.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Run as daemon'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Industrial Honeypot v1.0.0'
    )
    
    return parser.parse_args()


async def main():
    """Main application entry point."""
    args = parse_arguments()
    
    # Check if running as root (needed for low ports)
    if os.geteuid() != 0:
        print("Warning: Not running as root. May not be able to bind to privileged ports (< 1024)")
    
    try:
        # Initialize honeypot
        honeypot = IndustrialHoneypot(args.config)
        
        print("Starting Industrial Internet Honeypot...")
        print("Press Ctrl+C to stop")
        
        # Start the honeypot
        await honeypot.start()
        
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting honeypot: {e}")
        sys.exit(1)


def run():
    """Run the honeypot with proper event loop handling."""
    try:
        # Use uvloop if available for better performance
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            pass
            
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    run()