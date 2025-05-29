#!/usr/bin/env python3
"""
WithSecure API Security Events Collector and Syslog Converter
Versión mejorada con características de seguridad adicionales y mejor manejo de eventos
"""

import requests
import json
import logging
import os
import sys
from datetime import datetime, timedelta
import socket
import time
from pathlib import Path
import shutil
import stat
import hashlib
from logging.handlers import RotatingFileHandler
import tempfile
import re
from urllib3.util import Retry
from requests.adapters import HTTPAdapter
import base64
from typing import Dict, List, Set, Optional, Any
from operator import itemgetter

# Configure logging with rotation
HOME_DIR = str(Path.home())
LOG_DIR = "/var/log"
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5

class Config:
    """Constantes de configuración seguras."""
    BASE_URL = "https://api.connect.withsecure.com"
    TOKEN_ENDPOINT = f"{BASE_URL}/as/token.oauth2"
    WHOAMI_ENDPOINT = f"{BASE_URL}/whoami/v1/whoami"
    SECURITY_EVENTS_ENDPOINT = f"{BASE_URL}/security-events/v1/security-events"
    OUTPUT_FILE = "/var/log/withsecure.json"
    INDEX_FILE = "/var/log/withsecure_processed_ids.log"
    SYSLOG_FILE = "/var/log/withsecure.log"
    EVENTS_LOG_FILE = "/var/log/withsecure_events.log"
    CACHE_FILE = "/var/log/withsecure_cache.json"
    HOSTNAME = socket.gethostname()
    FACILITY = 1
    SEVERITY = 5
    MAX_JSON_SIZE = 50 * 1024 * 1024  # 50MB
    FILE_PERMISSIONS = 0o640
    DIR_PERMISSIONS = 0o750
    RETRY_ATTEMPTS = 3
    RETRY_BACKOFF = 2
    CACHE_MAX_AGE = 86400  # 24 horas en segundos
    REQUIRED_FIELDS = {
        "id", "severity", "serverTimestamp", "engine",
        "action", "clientTimestamp", "details"
    }
    # Todos los campos que queremos extraer de los eventos
    EVENT_FIELDS = {
        "id", "severity", "serverTimestamp", "clientTimestamp",
        "engine", "action", "userName", "persistenceTimestamp",
        "eventTransactionId"
    }
    # Campos específicos que queremos extraer de details
    DETAILS_FIELDS = {
        "isRemoteChange", "profileName", "newValue", "alertType",
        "profileVersion", "settingName", "throttledCount", "profileId",
        "hostIpAddress", "oldValue", "userPrincipalName", "reason",
        "process", "path", "url", "malware", "rule", "description", "infectionName",
        "creator"
    }

def ensure_secure_directory(directory: str, mode: int = Config.DIR_PERMISSIONS) -> None:
    """Asegurar que el directorio existe con permisos seguros."""
    os.makedirs(directory, mode=mode, exist_ok=True)
    current_mode = stat.S_IMODE(os.stat(directory).st_mode)
    if current_mode != mode:
        os.chmod(directory, mode)

ensure_secure_directory(LOG_DIR)

class SensitiveDataFilter(logging.Filter):
    """Filtro para redactar datos sensibles en los logs."""
    def __init__(self):
        super().__init__()
        self.patterns = [
            (r'Bearer [A-Za-z0-9-._~+/]+=*', 'Bearer [REDACTADO]'),
            (r'Basic [A-Za-z0-9-._~+/]+=*', 'Basic [REDACTADO]'),
            (r'auth_header="[^"]*"', 'auth_header="[REDACTADO]"'),
            (r'password="[^"]*"', 'password="[REDACTADO]"'),
            (r'id="[^"]*"', 'id="[REDACTADO]"'),
        ]

    def filter(self, record):
        if isinstance(record.msg, str):
            for pattern, replacement in self.patterns:
                record.msg = re.sub(pattern, replacement, record.msg)
        return True

log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'withsecure_events.log'),
    maxBytes=LOG_MAX_SIZE,
    backupCount=LOG_BACKUP_COUNT,
    mode='a'
)
file_handler.setFormatter(log_formatter)
file_handler.addFilter(SensitiveDataFilter())

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stdout),
        file_handler
    ]
)

logger = logging.getLogger('withsecure_events')

def get_required_env_var(var_name: str) -> str:
    """Obtener y validar una variable de entorno requerida."""
    value = os.environ.get(var_name)
    if not value:
        logger.error(f"Variable de entorno requerida {var_name} no establecida. Saliendo.")
        sys.exit(1)
    if not re.match(r'^[A-Za-z0-9+/=_\-\.]+$', value):
        logger.error(f"Caracteres inválidos en {var_name}. Saliendo.")
        sys.exit(1)
    return value

class EventCache:
    """Gestión de caché de eventos con limpieza automática."""
    def __init__(self):
        self.cache_file = Config.CACHE_FILE
        self.load_cache()

    def load_cache(self) -> None:
        """Cargar caché desde archivo con limpieza automática."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    current_time = time.time()
                    self.cache = {
                        k: v for k, v in cache_data.items()
                        if current_time - v['timestamp'] < Config.CACHE_MAX_AGE
                    }
            else:
                self.cache = {}
        except Exception as e:
            logger.error(f"Error al cargar caché: {e}")
            self.cache = {}

    def save_cache(self) -> None:
        """Guardar caché a archivo de forma segura."""
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                dir=os.path.dirname(self.cache_file),
                delete=False
            ) as temp_file:
                json.dump(self.cache, temp_file)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.chmod(temp_file.name, Config.FILE_PERMISSIONS)
            os.replace(temp_file.name, self.cache_file)
        except Exception as e:
            logger.error(f"Error al guardar caché: {e}")
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)

    def add_event(self, event_id: str, event_data: Dict) -> None:
        """Añadir evento al caché."""
        self.cache[event_id] = {
            'timestamp': time.time(),
            'data': event_data
        }
        self.save_cache()

    def get_event(self, event_id: str) -> Optional[Dict]:
        """Obtener evento del caché."""
        if event_id in self.cache:
            return self.cache[event_id]['data']
        return None

    def clear_old_entries(self) -> None:
        """Limpiar entradas antiguas del caché."""
        current_time = time.time()
        self.cache = {
            k: v for k, v in self.cache.items()
            if current_time - v['timestamp'] < Config.CACHE_MAX_AGE
        }
        self.save_cache()

event_cache = EventCache()

def validate_json_size(json_data: Dict) -> bool:
    """Validar tamaño de datos JSON."""
    size = len(json.dumps(json_data))
    if size > Config.MAX_JSON_SIZE:
        raise ValueError(f"Los datos JSON exceden el tamaño máximo de {Config.MAX_JSON_SIZE} bytes")
    return True

def validate_event_fields(event: Dict) -> bool:
    """Validar campos requeridos y formato del evento."""
    missing_fields = Config.REQUIRED_FIELDS - set(event.keys())
    if missing_fields:
        logger.warning(f"Campos requeridos faltantes: {', '.join(missing_fields)}")
        return False

    if not isinstance(event.get('details'), dict):
        logger.warning("Campo 'details' no es un diccionario válido")
        return False

    try:
        datetime.fromisoformat(event['serverTimestamp'].replace('Z', '+00:00'))
        datetime.fromisoformat(event['clientTimestamp'].replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        logger.warning("Formato de timestamp inválido")
        return False

    return True


def secure_file_write(filepath: str, content: str, mode: str = 'w') -> None:
    """Escribir contenido en archivo de forma segura con permisos apropiados."""
    temp_file = None
    try:
        dir_path = os.path.dirname(filepath)
        temp_file = tempfile.NamedTemporaryFile(
            mode=mode,
            dir=dir_path,
            delete=False
        )
        
        if isinstance(content, str):
            temp_file.write(content)
        elif isinstance(content, bytes):
            temp_file.buffer.write(content)
        
        temp_file.flush()
        os.fsync(temp_file.fileno())
        temp_file.close()
        
        os.chmod(temp_file.name, Config.FILE_PERMISSIONS)
        os.replace(temp_file.name, filepath)
        
    except Exception as e:
        logger.error(f"Error al escribir en el archivo {filepath}: {e}")
        if temp_file and os.path.exists(temp_file.name):
            os.unlink(temp_file.name)
        raise

def extract_event_fields(event: Dict) -> Dict:
    """Extraer todos los campos relevantes del evento."""
    fields = {}
    
    # Extraer campos base del evento
    for field in Config.EVENT_FIELDS:
        if field in event:
            fields[field] = event[field]
    
    # Extraer campos de device si existen
    if isinstance(event.get('device'), dict):
        for key, value in event['device'].items():
            if key != 'id':  # Excluir ID por seguridad
                fields[f'device_{key}'] = value
    
    # Extraer campos de organization si existen
    if isinstance(event.get('organization'), dict):
        for key, value in event['organization'].items():
            if key != 'id':  # Excluir ID por seguridad
                fields[f'organization_{key}'] = value
    
    # Extraer campos de details
    if isinstance(event.get('details'), dict):
        for field in Config.DETAILS_FIELDS:
            if field in event['details']:
                fields[field] = event['details'][field]
    
    return fields

def convert_to_syslog(event: Dict, collection_timestamp: str) -> Optional[str]:
    """Convertir evento a formato syslog con todos los campos disponibles."""
    try:
        # Extraer timestamp del evento para el formato syslog
        server_timestamp = event.get("serverTimestamp", "")
        if server_timestamp:
            try:
                dt = datetime.fromisoformat(server_timestamp.replace("Z", "+00:00"))
                timestamp = dt.strftime("%Y %b %d %H:%M:%S")
            except ValueError:
                timestamp = datetime.now().strftime("%Y %b %d %H:%M:%S")
        else:
            timestamp = datetime.now().strftime("%Y %b %d %H:%M:%S")
        
        def sanitize(value: Any) -> str:
            """Sanitizar valores para formato syslog."""
            if value is None:
                return ""
            str_value = str(value)
            return str_value.replace('"', '\\"').replace('\n', ' ').replace('\r', ' ')
        
        # Extraer todos los campos relevantes
        fields = extract_event_fields(event)
        
        # Construir mensaje syslog
        syslog_msg = f"{timestamp} {Config.HOSTNAME} withsecure-collector: "
        
        # Añadir campos en orden alfabético para consistencia
        field_strings = []
        for key, value in sorted(fields.items()):
            field_strings.append(f'{key}="{sanitize(value)}"')
        
        syslog_msg += " ".join(field_strings)
        
        # Añadir timestamp de recolección
        syslog_msg += f' collected_at="{sanitize(collection_timestamp)}"'
        
        return syslog_msg
    except Exception as e:
        logger.error(f"Error al convertir evento a syslog: {e}")
        return None


def save_to_log(data: Dict) -> bool:
    """Guardar datos en el log con seguridad mejorada y ordenamiento temporal."""
    try:
        if "items" not in data:
            logger.warning("No se encontraron 'items' en los datos")
            return False
        
        # Ordenar eventos por timestamp
        events = data["items"]
        try:
            events.sort(key=lambda x: x.get("serverTimestamp", ""), reverse=False)
        except Exception as e:
            logger.warning(f"Error al ordenar eventos: {e}")
        
        original_count = len(events)
        filtered_events = []
        duplicate_events = []
        new_event_ids = []
        
        # Obtener IDs de eventos existentes
        existing_ids = set()
        if os.path.exists(Config.INDEX_FILE):
            try:
                with open(Config.INDEX_FILE, 'r') as f:
                    existing_ids = set(json.load(f))
            except Exception as e:
                logger.error(f"Error al cargar IDs existentes: {e}")
        
        # Filtrar y procesar eventos
        collection_timestamp = datetime.now().isoformat()
        
        for event in events:
            if not validate_event_fields(event):
                logger.warning(f"Evento inválido encontrado: {event.get('id', 'ID desconocido')}")
                continue
            
            event_id = event.get("id")
            if not event_id:
                logger.warning("Evento sin ID encontrado, omitiendo")
                continue
            
            if event_id not in existing_ids:
                filtered_events.append(event)
                new_event_ids.append(event_id)
            else:
                duplicate_events.append(event_id)
        
        new_count = len(filtered_events)
        duplicate_count = len(duplicate_events)
        
        logger.info(f"Total de eventos recibidos: {original_count}")
        logger.info(f"Nuevos eventos a procesar: {new_count}")
        logger.info(f"Eventos duplicados omitidos: {duplicate_count}")
        
        if new_count == 0:
            logger.info("No hay nuevos eventos para guardar")
            return True
        
        # Procesar y escribir eventos
        try:
            # Escribir archivo JSON
            with tempfile.NamedTemporaryFile(mode='w', dir=os.path.dirname(Config.OUTPUT_FILE), delete=False) as temp_json:
                for event in filtered_events:
                    merged_event = {**event, "withsecure": True, "collected_at": collection_timestamp}
                    json.dump(merged_event, temp_json)
                    temp_json.write('\n')
                
                temp_json.flush()
                os.fsync(temp_json.fileno())
                
            os.chmod(temp_json.name, Config.FILE_PERMISSIONS)
            os.replace(temp_json.name, Config.OUTPUT_FILE)
            
            # Escribir archivo syslog
            with tempfile.NamedTemporaryFile(mode='a', dir=os.path.dirname(Config.SYSLOG_FILE), delete=False) as temp_syslog:
                for event in filtered_events:
                    syslog_line = convert_to_syslog(event, collection_timestamp)
                    if syslog_line:
                        temp_syslog.write(syslog_line + '\n')
                
                temp_syslog.flush()
                os.fsync(temp_syslog.fileno())
                
            os.chmod(temp_syslog.name, Config.FILE_PERMISSIONS)
            os.replace(temp_syslog.name, Config.SYSLOG_FILE)
            
            # Actualizar archivo de índice
            all_ids = list(existing_ids | set(new_event_ids))
            with tempfile.NamedTemporaryFile(mode='a', dir=os.path.dirname(Config.INDEX_FILE), delete=False) as temp_index:
                json.dump(all_ids, temp_index)
                temp_index.flush()
                os.fsync(temp_index.fileno())
                
            os.chmod(temp_index.name, Config.FILE_PERMISSIONS)
            os.replace(temp_index.name, Config.INDEX_FILE)
            
            logger.info(f"Se guardaron {new_count} eventos en los archivos de log exitosamente")
            return True
            
        except Exception as e:
            logger.error(f"Error al escribir eventos en archivos: {e}")
            return False
            
    except Exception as e:
        logger.exception(f"Error en save_to_log: {e}")
        return False

def create_secure_session() -> requests.Session:
    """Crear una sesión HTTP segura con lógica de reintentos."""
    session = requests.Session()
    retry_strategy = Retry(
        total=Config.RETRY_ATTEMPTS,
        backoff_factor=Config.RETRY_BACKOFF,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.verify = True
    return session

def get_auth_token(auth_header: str) -> Optional[str]:
    """Obtener token de autenticación con seguridad mejorada."""
    session = create_secure_session()
    try:
        headers = {
            "Authorization": f"Basic {auth_header}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = "grant_type=client_credentials"
        
        response = session.post(Config.TOKEN_ENDPOINT, headers=headers, data=payload)
        
        if response.status_code == 200:
            data = response.json()
            logger.info("Token de autenticación obtenido exitosamente")
            return data.get("access_token")
        else:
            logger.error(f"Error al obtener token de autenticación: {response.status_code}")
            return None
    except Exception as e:
        logger.exception("Error al obtener token de autenticación")
        return None
    finally:
        session.close()

def verify_token(token: str) -> bool:
    """Verificar token con seguridad mejorada."""
    session = create_secure_session()
    try:
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        response = session.get(Config.WHOAMI_ENDPOINT, headers=headers)
        
        if response.status_code == 200:
            logger.info("Token verificado exitosamente")
            return True
        else:
            logger.warning("Verificación del token fallida")
            return False
    except Exception as e:
        logger.exception("Error al verificar token")
        return False
    finally:
        session.close()

def fetch_security_events(token: str, organization_id: str, engine_group: str) -> Optional[Dict]:
    """Obtener eventos de seguridad con seguridad mejorada."""
    session = create_secure_session()
    try:
        days = 90
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"
        }
        
        params = {
            "organizationId": organization_id,
            "persistenceTimestampStart": start_str,
            "persistenceTimestampEnd": end_str,
            "limit": 1000
        }
        
        if engine_group:
            params["engineGroup"] = engine_group
        
        response = session.get(Config.SECURITY_EVENTS_ENDPOINT, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            validate_json_size(data)
            event_count = len(data.get("items", []))
            logger.info(f"Se obtuvieron {event_count} eventos de seguridad exitosamente de los últimos {days} dias")
            return data
        else:
            logger.error(f"Error al obtener eventos de seguridad: {response.status_code}, Response: {response.text}")
            return None
    except Exception as e:
        logger.exception("Error al obtener eventos de seguridad")
        return None
    finally:
        session.close()

def main() -> int:
    """Función principal con características de seguridad mejoradas."""
    try:
        logger.info("Iniciando recolector y conversor integrado de WithSecure")
        
        # Asegurar permisos de archivo correctos para todos los archivos de log
        for log_file in [Config.OUTPUT_FILE, Config.INDEX_FILE, Config.SYSLOG_FILE]:
            if os.path.exists(log_file):
                os.chmod(log_file, Config.FILE_PERMISSIONS)
        
        # Validar variables de entorno
        auth_header = get_required_env_var("WITHSECURE_AUTH")
        try:
            base64.b64decode(auth_header)
        except Exception:
            logger.error("WITHSECURE_AUTH no es un base64 válido. Saliendo.")
            return 1

        organization_id = get_required_env_var("WITHSECURE_ORG_ID")
        engine_group = os.environ.get("WITHSECURE_ENGINE_GROUP", "")
        
        # Obtener token de autenticación
        token = get_auth_token(auth_header)
        if not token:
            logger.error("Error al obtener token de autenticación. Saliendo.")
            return 1
        
        # Verificar token
        if not verify_token(token):
            logger.error("Verificación de token fallida. Saliendo.")
            return 1
        
        # Obtener eventos de seguridad
        data = fetch_security_events(token, organization_id, engine_group)
        if not data:
            logger.error("Error al obtener eventos de seguridad. Saliendo.")
            return 1
        
        # Limpiar caché antigua
        event_cache.clear_old_entries()
        
        # Guardar datos en archivos de log
        if not save_to_log(data):
            logger.error("Error al guardar datos en el log. Saliendo.")
            return 1
        
        logger.info("-----------------------------------------------------------------------------------")
        logger.info("Recolección y conversión de eventos de seguridad WithSecure completada exitosamente")
        logger.info("-----------------------------------------------------------------------------------")
        return 0
        
    except Exception as e:
        logger.exception(f"Error no manejado en la función principal: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
