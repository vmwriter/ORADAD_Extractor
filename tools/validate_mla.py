#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sys
import gzip
import logging
from typing import Union, BinaryIO

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s'
    )
    return logging.getLogger('validate_mla')

def open_file(file_path: str) -> Union[BinaryIO, gzip.GzipFile]:
    """Open MLA file, handling both compressed and uncompressed formats."""
    if file_path.endswith('.gz'):
        return gzip.open(file_path, 'rb')
    return open(file_path, 'rb')

def validate_mla_file(file_path: str, logger: logging.Logger) -> bool:
    """Validate an MLA file structure."""
    try:
        with open_file(file_path) as f:
            logger.info(f"Checking file: {file_path}")
            
            # Try parsing XML
            tree = ET.parse(f)
            root = tree.getroot()
            
            # Check for required elements
            domains = root.findall(".//domain")
            if not domains:
                logger.error("No domain elements found")
                return False
            
            # Validate each domain
            for domain in domains:
                domain_name = domain.get('name')
                if not domain_name:
                    logger.error("Found domain without name attribute")
                    return False
                
                logger.info(f"Found domain: {domain_name}")
                
                # Check for entries
                entries = domain.findall(".//entry")
                if not entries:
                    logger.warning(f"No entries found in domain {domain_name}")
                    continue
                
                # Count object types
                object_types = {}
                for entry in entries:
                    obj_class = entry.find("./objectClass")
                    if obj_class is not None and obj_class.text:
                        obj_type = obj_class.text.lower()
                        object_types[obj_type] = object_types.get(obj_type, 0) + 1
                
                logger.info(f"Domain {domain_name} contains:")
                for obj_type, count in object_types.items():
                    logger.info(f"  - {count} {obj_type} objects")
            
            return True
            
    except gzip.BadGzipFile:
        logger.error("Invalid gzip file format")
        return False
    except ET.ParseError as e:
        logger.error(f"Invalid XML format: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return False

def main():
    logger = setup_logging()
    
    if len(sys.argv) != 2:
        logger.error("Usage: validate_mla.py <mla_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if validate_mla_file(file_path, logger):
        logger.info("File validation successful")
        sys.exit(0)
    else:
        logger.error("File validation failed")
        sys.exit(1)

if __name__ == '__main__':
    main() 