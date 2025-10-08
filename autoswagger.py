#!/usr/bin/env python3
# Autoswagger - Cale Anderson @ Intruder    
import argparse
import json
import os
import re
import sys
import threading
import time
from itertools import product as itertools_product
from urllib.parse import urljoin, urlencode, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from dicttoxml import dicttoxml
import yaml
import xml.etree.ElementTree as ET
from datetime import datetime

from concurrent.futures import ThreadPoolExecutor, as_completed

# Import Presidio for PII detection
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, Pattern, PatternRecognizer

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.logging import RichHandler
import logging

# ------------------------------
# Global Variables for Stats
# ------------------------------
TOTAL_REQUESTS = 0       # Tracks total requests sent by the tool
SCAN_START_TIME = 0.0    # Records scan start time (for RPS calculation)
SCAN_END_TIME = 0.0      # Records scan end time (for RPS calculation)

# Initialize Presidio Analyzer with custom recognizers
registry = RecognizerRegistry()

# Initialize file_handler for log data output
file_handler = None

def setup_pii_recognizers():
    """
    Adds custom recognizers for Person, Phone, Email, and Address to the Presidio registry
    with context words. Each recognizer uses a pattern and context to detect potential PII.
    """
    # Person
    person_pattern = Pattern(
        name="person", 
        regex=r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b", 
        score=0.85
    )
    person_recognizer = PatternRecognizer(
        supported_entity="PERSON", 
        patterns=[person_pattern],
        context=["name","first_name","last_name","firstname","lastname"]
    )

    # Phone Number
    phone_pattern = Pattern(
        name="phone_number", 
        regex=r"(\+?\d{1,3}[-.\s]?(\d{3})[-.\s]?(\d{3,4})[-.\s]?(\d{4}))", 
        score=0.85
    )
    phone_recognizer = PatternRecognizer(
        supported_entity="PHONE_NUMBER", 
        patterns=[phone_pattern],
        context=["phone","mobile","telephone","tel","phone_number"]
    )

    # Email Address
    email_pattern = Pattern(
        name="email", 
        regex=r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", 
        score=0.85
    )
    email_recognizer = PatternRecognizer(
        supported_entity="EMAIL_ADDRESS", 
        patterns=[email_pattern],
        context=["email","email_address","contact"]
    )

    # Address
    address_pattern = Pattern(
        name="address", 
        regex=r"\b\d{1,5}\s\w+\s\w+\b", 
        score=0.85
    )
    address_recognizer = PatternRecognizer(
        supported_entity="ADDRESS", 
        patterns=[address_pattern],
        context=["addr","address","location"]
    )

    # Add each recognizer to the registry
    registry.add_recognizer(person_recognizer)
    registry.add_recognizer(phone_recognizer)
    registry.add_recognizer(email_recognizer)
    registry.add_recognizer(address_recognizer)

# Call setup function to prepare custom PII recognizers
setup_pii_recognizers()

# Initialize Presidio context-aware enhancer
from presidio_analyzer.context_aware_enhancers import LemmaContextAwareEnhancer

context_aware_enhancer = LemmaContextAwareEnhancer(
    context_similarity_factor=0.35,
    min_score_with_context_similarity=0.4
)

# Analyzer engine for detection
analyzer = AnalyzerEngine(
    registry=registry,
    context_aware_enhancer=context_aware_enhancer
)

# Initialize Rich Console for formatted output
console = Console()

# Suppress warnings about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default request timeout
TIMEOUT = 10

# Paths for detecting swagger/openapi specs in UI or direct spec endpoints
SWAGGER_UI_PATHS = sorted({
    "/", "/apidocs/", "/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html",
    "/swagger/swagger-ui.html", "/api/swagger-ui.html", "/api_docs", "/api/index.html",
    "/api/doc", "/api/docs/", "/api/swagger/index.html", "/api/swagger/swagger-ui.html",
    "/api/swagger-ui/api-docs", "/api/api-docs", "/api/apidocs", "/api/swagger",
    "/api/swagger/static/index.html", "/api/swagger-resources",
    "/api/swagger-resources/restservices/v2/api-docs", "/api/__swagger__/", "/api/_swagger_/",
    "/docu", "/docs", "/swagger", "/api-doc", "/doc/",
    "/webjars/swagger-ui/index.html", "/3.0.0/swagger-ui.html",
    "/MobiControl/api/docs/index/index.html", "/Swagger", "/Swagger/", "/Swagger/index.html",
    "/V2/api-docs/ui", "/admin/swagger-ui/index.html", "/api-doc/", "/api-docs/",
    "/api-docs/ui/", "/api-docs/v1/index.html", "/api-documentation/index.html",
    "/api/", "/api/api-docs", "/api/api-docs/index.html", "/api/api/",
    "/api/apidocs", "/api/config", "/api/doc", "/api/doc/", "/api/spec/", "/spec/",
})

DIRECT_SPEC_PATHS = sorted({
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/v1/swagger.json",
    "/v1/swagger.yaml", "/v1/swagger.yml", "/openapi.json",
    "/openapi.yaml", "/openapi.yml", "/api/openapi.json",
    "/api/openapi.yaml", "/api/openapi.yml", "/docs/swagger.json",
    "/docs/swagger.yaml", "/docs/openapi.json", "/docs/openapi.yaml",
    "/api-docs/swagger.json", "/api-docs/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
    "/rest/swagger.json", "/rest/swagger.yaml", "/rest-api/swagger.json",
    "/swagger/v1/docs.json", "/api/swagger/docs.json",
    "/swagger/docs/v1.json", "/swagger/swagger.json", "/swagger/swagger.yaml",
    "/api-doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
    "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
    "/api/swagger_doc.json", "/v2/swagger.json", "/v2/swagger.yaml",
    "/v3/swagger.json", "/v3/swagger.yaml", "/openapi2.json",
    "/openapi2.yaml", "/openapi2.yml", "/api/v3/openapi.json",
    "/api/v3/openapi.yaml", "/api/v3/openapi.yml", "/spec/swagger.json",
    "/spec/swagger.yaml", "/spec/openapi.json", "/spec/openapi.yaml",
    "/api-docs/swagger-ui.json", "/api-docs/swagger-ui.yaml",
    "/api-docs/openapi.json", "/api-docs/openapi.yaml",
    "/swagger-ui.json", "/swagger-ui.yaml"
})

# Regex patterns for secrets (similar to TruffleHog)
TRUFFLEHOG_REGEXES = {
    "Slack Token": r"(xox[pborsa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": r"-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": r"da2-[a-z0-9]{26}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"[fF][aA][cC][eE][bB][oO][oO][kK].*['\"]?[0-9a-f]{32}['\"]?",
    "GitHub": r"[gG][iI][tT][hH][uU][bB].*['\"]?[0-9a-zA-Z]{35,40}['\"]?",
    "Generic API Key": r"[aA][pP][iI]_?[kK][eE][yY].*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
    "Generic Secret": r"[sS][eE][cC][rR][eE][tT].*['\"]?[0-9a-zA-Z]{32,45}['\"]?",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Password in URL": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}['\"\s]",
    "PayPal Braintree Access Token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Telegram Bot API Key": r"[0-9]+:AA[0-9A-Za-z\-_]{33}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twitter Access Token": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": r"[tT][wW][iI][tT][tT][eE][rR].*['\"]?[0-9a-zA-Z]{35,44}['\"]?"
}

# Compile the regexes for performance
COMPILED_TRUFFLEHOG_REGEXES = {name: re.compile(pattern) for name, pattern in TRUFFLEHOG_REGEXES.items()}

# Debug info regex pattern
DEBUG_INFO_PATTERN = re.compile(r'\b(?:env\.[A-Za-z_]+|AWS_[A-Z_]+|AZURE_[A-Z_]+|DEBUG|ERROR)\b')

# Default test values for parameters by type
TEST_VALUES = {
    "integer": [1, 2, 100, -1, 0, 999, 123456],
    "string": [
        "1", "test", "example", "1234", "none", "admin", "guest", "user@email.com",
        "550e8400-e29b-41d4-a716-446655440000",
        "a8098c1a-f86e-11da-bd1a-00112444be1e"
    ],
    "boolean": [True, False],
    "number": [1, 0, 100, 1000, 0.1],
    "base64": ["MQ==", "dXNlcjE=", "YWRtaW4xMjM=", "c2FtcGxlVXNlcg=="],
    "default": ["1", "test", "123", "True","true","550e8400-e29b-41d4-a716-446655440000", "*", "All"]
}

# Lock for thread-safe operations
lock = threading.Lock()

# Initialize logger with RichHandler
logger = logging.getLogger("autoswagger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(message)s")

# Set to track hosts where no valid swagger was found
bad_hosts = set()

def get_timestamp():
    """
    Returns current timestamp in the format [HH:MM:SS].
    Used for logging messages with a consistent time prefix.
    """
    return time.strftime("[%H:%M:%S]")

def log(message, level="INFO"):
    """
    Logs a message with a given level to both the Rich console and the optional file_handler.

    :param message: String message to log
    :param level: Logging level ('INFO', 'DEBUG', 'WARNING', 'CRITICAL', 'SUCCESS')
    """
    global file_handler
    timestamp = get_timestamp()
    levels = {
        "INFO": "[green][INFO][/green]",
        "DEBUG": "[cyan][DEBUG][/cyan]",
        "WARNING": "[yellow][WARNING][/yellow]",
        "CRITICAL": "[red][CRITICAL][/red]",
        "SUCCESS": "[bold green][SUCCESS][/bold green]"
    }
    level_prefix = levels.get(level, f"[{level}]")
    formatted_message = f"{timestamp} {level_prefix} {message}"
    console.print(formatted_message, highlight=False)
    if file_handler and level == "DEBUG":
        logger.debug(message)
    elif file_handler and level in ["INFO", "WARNING", "CRITICAL", "SUCCESS"]:
        logger.info(message)

def print_banner():
    """
    Prints the ASCII banner for Autoswagger with intruder.io link in yellow.
    Called if not in product mode, to show the standard header.
    """
    banner = f"""[white]
      /   | __  __/ /_____  ______      ______ _____ _____ ____  _____
     / /| |/ / / / __/ __ \\/ ___/ | /| / / __ `/ __ `/ __ `/ _ \\/ ___/
    / ___ / /_/ / /_/ /_/ (__  )| |/ |/ / /_/ / /_/ / /_/ /  __/ /
    /_/  |_\\__,_/\\__/\\____/____/ |__/|__/_\\__,_/\\__, /\\__, /\\___/_/
                                              /____//____/[/white]
                              [yellow]https://intruder.io[/yellow]
                          Find unauthenticated endpoints
    """
    console.print(banner)

def generate_parameter_values(param_type, enum=None):
    """
    Returns a list of test values for a given parameter type.
    If an enum list is provided, uses that instead of defaults.
    """
    if enum:
        return enum
    return TEST_VALUES.get(param_type, TEST_VALUES["default"])

def build_nested_object(schema, value_index=0):
    """
    Recursively constructs a nested object (dict) for complex schemas.
    Handles properties, arrays, and composite references (oneOf, anyOf, allOf).
    """
    obj = {}
    for key, prop in schema.get('properties', {}).items():
        if '$ref' in prop:
            continue
        if 'oneOf' in prop or 'anyOf' in prop or 'allOf' in prop:
            obj[key] = handle_composite_schemas(prop, value_index)
        elif prop.get('type') == 'object':
            obj[key] = build_nested_object(prop, value_index)
        elif prop.get('type') == 'array':
            obj[key] = build_array_item(prop, value_index)
        else:
            param_type = prop.get('type', 'string')
            enum = prop.get('enum', None)
            values = generate_parameter_values(param_type, enum)
            obj[key] = values[value_index % len(values)]
    return obj

def handle_composite_schemas(schema, value_index=0):
    """
    Handles composite schema definitions like oneOf, anyOf, and allOf.
    Calls build_nested_object recursively on the chosen sub-schema or the combined properties.
    """
    if 'oneOf' in schema:
        return build_nested_object(schema['oneOf'][value_index % len(schema['oneOf'])], value_index)
    elif 'anyOf' in schema:
        return build_nested_object(schema['anyOf'][value_index % len(schema['anyOf'])], value_index)
    elif 'allOf' in schema:
        combined_schema = {}
        for sub_schema in schema['allOf']:
            combined_schema.update(sub_schema.get('properties', {}))
        return build_nested_object({'properties': combined_schema}, value_index)
    return build_nested_object(schema, value_index)

def build_array_item(item_schema, value_index=0):
    """
    Builds an array item from the given schema.
    If the schema is an object or contains properties, delegates to build_nested_object.
    Otherwise chooses from test values by type.
    """
    if 'properties' in item_schema or item_schema.get('type') == 'object':
        return build_nested_object(item_schema, value_index)
    else:
        param_type = item_schema.get('type', 'string')
        enum = item_schema.get('enum', None)
        values = generate_parameter_values(param_type, enum)
        return values[value_index % len(values)]

def build_file_upload_body(schema, content_type, value_index=0):
    """
    Builds a simple file upload body for multipart/form-data.
    Returns a dict with a file-like tuple if content_type is multipart/form-data.
    """
    if content_type == 'multipart/form-data':
        return {'file': ('test.txt', b'This is a test file')}
    return None

def build_request_body(schema, content_type, value_index=0):
    """
    Builds a request body based on the schema and specified content type.
    Supports JSON, XML, form-encoded, plain text, octet-stream, and multipart.
    """
    if not schema:
        return None

    if 'oneOf' in schema or 'anyOf' in schema or 'allOf' in schema:
        body = handle_composite_schemas(schema, value_index)
    elif schema.get('type') == 'array':
        item_schema = schema.get('items', {})
        body = [build_array_item(item_schema, value_index)]
    elif schema.get('type') == 'object':
        body = build_nested_object(schema, value_index)
    else:
        param_type = schema.get('type', 'string')
        enum = schema.get('enum', None)
        values = generate_parameter_values(param_type, enum)
        body = values[value_index % len(values)]

    if content_type == 'application/x-www-form-urlencoded':
        return urlencode(body)
    elif content_type == 'application/xml':
        return dicttoxml(body).decode()
    elif content_type == 'application/json':
        return json.dumps(body)
    elif content_type == 'text/plain':
        return str(body)
    elif content_type == 'application/octet-stream':
        return b'\x00\x01\x02'
    elif content_type == 'multipart/form-data':
        return build_file_upload_body(schema, content_type, value_index)
    return json.dumps(body)

def substitute_path_parameters(path, parameters, value_mapping):
    """
    Replaces path parameter placeholders (e.g. {id}, :id, <id>) with generated values.
    """
    for param in parameters:
        if param.get('in') == 'path':
            param_name = param.get('name')
            value = value_mapping.get(param_name)
            if value is not None:
                path = re.sub(rf'{{{param_name}}}|:{param_name}|<{param_name}>', str(value), path)
    return path

def generate_query_string(parameters, value_mapping):
    """
    Creates a query string (e.g. ?key=value) for parameters that are in the query location.
    """
    query_params = {}
    for param in parameters:
        if param.get('in') == 'query':
            param_name = param.get('name')
            value = value_mapping.get(param_name)
            if value is not None:
                query_params[param_name] = value
    return urlencode(query_params)

def detect_sensitive_info(content):
    """
    Searches the response content for known secret patterns (TruffleHog) and debug info patterns.
    Returns a dict of matches if found, along with the regex patterns used.
    """
    sensitive_info = {}
    regex_patterns = {}

    for name, pattern in COMPILED_TRUFFLEHOG_REGEXES.items():
        matches = pattern.findall(content)
        if matches:
            sensitive_info.setdefault(name, []).extend(matches)
            regex_patterns[name] = pattern.pattern

    debug_info_found = DEBUG_INFO_PATTERN.findall(content)
    if debug_info_found:
        sensitive_info.setdefault('Debug Information', []).extend(debug_info_found)
        regex_patterns['Debug Information'] = DEBUG_INFO_PATTERN.pattern

    return sensitive_info if sensitive_info else None, regex_patterns

def is_large_response(content):
    """
    Checks if the response is large, specifically:
    - Contains 100+ items in JSON arrays or dictionary keys
    - Or 100+ elements in XML
    - Or raw content_length > 100000 bytes
    """
    try:
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        if content.strip().startswith('{') or content.strip().startswith('['):
            data = json.loads(content)
            if isinstance(data, list) and len(data) >= 100:
                return True
            elif isinstance(data, dict):
                total_items = sum(1 for _ in data.values())
                if total_items >= 100:
                    return True
        elif content.strip().startswith('<'):
            root = ET.fromstring(content)
            total_elements = sum(1 for _ in root.iter())
            if total_elements >= 100:
                return True
    except (json.JSONDecodeError, ET.ParseError):
        pass
    return False

def test_parameter_values(method, headers, base_url_no_path, full_path, parameters, request_body, content_type, rate, include_all, verbose, brute=False):
    """
    Tests parameter values for a given method/endpoint.
    If brute is false, only a single default set is tested.
    If brute is true, tries enumerating multiple data types/values.
    """
    best_response = None
    value_mapping = {}

    # Collect a default mapping from the parameter schema
    for param in parameters:
        if param.get('in') not in ['path', 'query']:
            continue
        param_name = param.get('name')
        schema = param.get('schema', {})
        param_type = schema.get('type', 'string')
        enum = schema.get('enum', None)
        values = generate_parameter_values(param_type, enum)
        value_mapping[param_name] = values[0]

    # Default mode: one request
    if not brute:
        response = send_request(
            method, headers, base_url_no_path, full_path, parameters,
            value_mapping, request_body, content_type, rate, include_all, verbose
        )
        return [response] if response else []

    # Brute mode: enumerates multiple combos or data types
    else:
        tested_types = set()
        param_types = []
        for param in parameters:
            if param.get('in') not in ['path', 'query']:
                continue
            schema = param.get('schema', {})
            param_type = schema.get('type', None)
            enum = schema.get('enum', None)
            if param_type:
                values = generate_parameter_values(param_type, enum)
            else:
                values = []
            param_types.append((param_type, values))

        # If all parameters have known values
        if all(vals for _, vals in param_types):
            param_test_values = [vals for _, vals in param_types]
            combos = itertools_product(*param_test_values)
            for combo in combos:
                val_map = {n: v for n, v in zip(value_mapping.keys(), combo)}
                resp = send_request(
                    method, headers, base_url_no_path, full_path, parameters,
                    val_map, request_body, content_type, rate, include_all, verbose
                )
                if resp:
                    return [resp]
        else:
            # Try different fallback types
            for test_type in ['integer', 'string', 'boolean', 'number']:
                if test_type in tested_types:
                    continue
                tested_types.add(test_type)
                param_test_values = [generate_parameter_values(test_type) for _ in value_mapping.keys()]
                first_combos = itertools_product(*[vals[:1] for vals in param_test_values])
                for combo in first_combos:
                    val_map = {n: v for n, v in zip(value_mapping.keys(), combo)}
                    resp = send_request(
                        method, headers, base_url_no_path, full_path, parameters,
                        val_map, request_body, content_type, rate, include_all, verbose
                    )
                    if resp:
                        max_clen = resp['content_length']
                        best_response = resp
                        second_combos = itertools_product(*param_test_values)
                        for combo2 in second_combos:
                            val_map2 = {n: v2 for n, v2 in zip(value_mapping.keys(), combo2)}
                            resp2 = send_request(
                                method, headers, base_url_no_path, full_path, parameters,
                                val_map2, request_body, content_type, rate, include_all, verbose
                            )
                            if resp2 and resp2['content_length'] > max_clen:
                                max_clen = resp2['content_length']
                                best_response = resp2
                        return [best_response]
    return []

def send_request(method, headers, base_url_no_path, full_path, parameters, value_mapping, request_body, content_type, rate, include_all, verbose):
    """
    Sends a request to the computed endpoint, respecting rate limit.
    Decodes the response, checks for secrets, PII (via line-based CSV and key:value scanning),
    returns a dictionary summarizing the result (status code, content length, PII, etc.)
    Skips 401 and 403 responses by default.
    """
    global TOTAL_REQUESTS

    substituted_path = substitute_path_parameters(full_path, parameters, value_mapping)
    query_string = generate_query_string(parameters, value_mapping)

    if not substituted_path.startswith('/'):
        substituted_path = '/' + substituted_path

    parsed_path = urlparse(substituted_path)
    if parsed_path.scheme in ['http', 'https']:
        full_url = substituted_path
    else:
        if query_string:
            full_url = f"{urljoin(base_url_no_path, substituted_path)}?{query_string}"
        else:
            full_url = urljoin(base_url_no_path, substituted_path)

    # headers = {'Content-Type': content_type} if content_type else {}
    headers.update({'Content-Type': content_type} if content_type else {})
    data = request_body if method.upper() in ['POST', 'PUT', 'PATCH'] else None

    try:
        if rate > 0:
            time.sleep(1.0 / rate)  # Rate limiting
        TOTAL_REQUESTS += 1

        response = requests.request(
            method, full_url, headers=headers, data=data,
            verify=False, allow_redirects=False, timeout=TIMEOUT
        )
        status_code = response.status_code

        # Skip 401 and 403 by design
        if status_code in [401, 403]:
            if verbose:
                log(f"Skipping endpoint {method.upper()} {full_url} due to status code {status_code}", level="INFO")
            return None

        content_length = len(response.content)
        try:
            content_text = response.content.decode('utf-8', errors='ignore')
        except Exception:
            content_text = ''

        # Detect secrets in entire content
        sensitive_info, regex_patterns = detect_sensitive_info(content_text)

        lines = content_text.splitlines()
        pii_detected = False
        pii_data = {}
        pii_detection_methods = set()
        interesting_response = False

        context_keywords = ["name", "email", "phone", "addr", "tel", "contact", "location"]

        # Simple CSV detection: check first line for multiple commas
        csv_header = []
        if len(lines) > 0:
            first_line = lines[0]
            columns = first_line.split(',')
            if len(columns) >= 3:
                csv_header = [col.strip().lower() for col in columns]

        # If CSV header recognized, parse subsequent lines with the same number of columns
        if csv_header:
            for idx, line in enumerate(lines):
                if idx == 0:
                    continue
                row_cols = line.split(',')
                if len(row_cols) == len(csv_header):
                    for i, col_name in enumerate(csv_header):
                        for kw in context_keywords:
                            if kw in col_name:
                                cell_value = row_cols[i].strip()
                                pres_res = analyzer.analyze(
                                    text=cell_value,
                                    entities=["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","ADDRESS"],
                                    language='en'
                                )
                                if pres_res:
                                    pii_detected = True
                                    for ent in pres_res:
                                        entity_type = ent.entity_type
                                        entity_value = cell_value[ent.start:ent.end]
                                        detection_method = 'context'
                                        pii_data.setdefault(entity_type, {'values': set(), 'detection_methods': set()})
                                        pii_data[entity_type]['values'].add(entity_value)
                                        pii_data[entity_type]['detection_methods'].add(detection_method)
                                        pii_detection_methods.add(detection_method)

        # Also do a naive "key: value" detection line by line
        for line in lines:
            if ':' in line:
                parts = line.split(':', 1)
                key_part = parts[0].strip().lower()
                val_part = parts[1].strip()

                for kw in context_keywords:
                    if kw in key_part:
                        pres_res = analyzer.analyze(
                            text=val_part,
                            entities=["PERSON","EMAIL_ADDRESS","PHONE_NUMBER","ADDRESS"],
                            language='en'
                        )
                        if pres_res:
                            pii_detected = True
                            for ent in pres_res:
                                entity_type = ent.entity_type
                                entity_value = val_part[ent.start:ent.end]
                                detection_method = 'context'
                                pii_data.setdefault(entity_type, {'values': set(), 'detection_methods': set()})
                                pii_data[entity_type]['values'].add(entity_value)
                                pii_data[entity_type]['detection_methods'].add(detection_method)
                                pii_detection_methods.add(detection_method)

        if pii_data:
            for entity_type in pii_data:
                pii_data[entity_type]['values'] = list(pii_data[entity_type]['values'])[:2]
                pii_data[entity_type]['detection_methods'] = list(pii_data[entity_type]['detection_methods'])

        # Mark interesting if 200 (or 404 if include_all) plus big or has PII
        if status_code == 200 or (include_all and status_code == 404):
            if is_large_response(response.content) or content_length > 100000:
                interesting_response = True
            if pii_detected:
                interesting_response = True

        result = {
            "method": method.upper(),
            "url": full_url,
            "path_template": full_path,
            "body": data if data else "",
            "status_code": status_code,
            "content_length": content_length,
            "pii_detected": pii_detected,
            "pii_data": None,
            "pii_detection_details": None,
            "interesting_response": interesting_response,
            "regex_patterns_found": {}
        }

        if pii_detected:
            result["pii_data"] = {k: list(vv['values']) for k, vv in pii_data.items()}
            detection_details = {}
            for k, vv in pii_data.items():
                detection_details[k] = {
                    "detection_methods": list(vv['detection_methods'])
                }
            result["pii_detection_details"] = detection_details

        # If TruffleHog found sensitive_info, merge that with the same pii_data structure
        if sensitive_info:
            result["regex_patterns_found"] = {}
            result["pii_detected"] = True
            for key, values in sensitive_info.items():
                detection_method = 'regex'
                if key not in pii_data:
                    pii_data[key] = {'values': set(), 'detection_methods': set()}
                pii_data[key]['values'].update(values)
                pii_data[key]['detection_methods'].add(detection_method)
                pii_detection_methods.add(detection_method)
                result["regex_patterns_found"][key] = regex_patterns[key]

            result["pii_data"] = {k: list(vv['values'])[:2] for k, vv in pii_data.items()}
            detection_details = {}
            for k, vv in pii_data.items():
                detection_details[k] = {
                    "detection_methods": list(vv['detection_methods'])
                }
            result["pii_detection_details"] = detection_details
            result["pii_detected"] = True
            if (status_code == 200 or (include_all and status_code == 404)):
                interesting_response = True
            result["interesting_response"] = interesting_response

        if verbose:
            if status_code == 200:
                log(f"{method.upper()} {full_url} returned {status_code}", level="SUCCESS")
            elif status_code == 404 and include_all:
                log(f"{method.upper()} {full_url} returned {status_code}", level="WARNING")
            elif 400 <= status_code < 600:
                log(f"{method.upper()} {full_url} returned {status_code}", level="WARNING")
            else:
                log(f"{method.upper()} {full_url} returned {status_code}", level="INFO")

        return result

    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error testing {method.upper()} {full_url}: {e}", level="DEBUG")
    return None

def test_endpoint(base_url, headers, base_path, path_template, method, parameters, request_body=None,
                  content_type=None, verbose=False, rate=30, include_all=False,
                  product_mode=False, brute=False):
    """
    Tests a single endpoint (method + path_template).
    Prepares final path by combining base_path with path_template, then calls test_parameter_values.
    Returns a list of results from that function.
    """
    if base_path and not base_path.startswith("/"):
        base_path = "/" + base_path
    if base_path.endswith("/"):
        base_path = base_path[:-1]

    full_path = base_path + path_template
    parsed_base_url = urlparse(base_url)
    base_url_no_path = f"{parsed_base_url.scheme}://{parsed_base_url.netloc}"

    results = []
    try:
        start_time = time.time()
        endpoint_results = test_parameter_values(
            method, headers, base_url_no_path, full_path, parameters,
            request_body, content_type, rate, include_all, verbose, brute=brute
        )
        if endpoint_results:
            results.extend(endpoint_results)
    except Exception as e:
        if verbose:
            log(f"Error testing endpoint {method.upper()} {full_path}: {e}", level="DEBUG")
    finally:
        elapsed_time = time.time() - start_time
        if elapsed_time > TIMEOUT and verbose:
            log(f"Timeout reached while testing endpoint {method.upper()} {full_path}", level="WARNING")

    return results

def test_endpoints(base_url, headers, base_path, swagger_spec, verbose=False,
                   include_risk=False, include_all=False, product_mode=False,
                   rate=30, tried_basepath_fallback=False, brute=False):
    """
    Iterates over all paths and methods in the provided swagger_spec.
    Submits tasks to test_endpoint if the method is allowed (GET or others if -risk).
    Returns all aggregated results. Also includes fallback if 80%+ are 404.
    """
    results = []
    if not swagger_spec or 'paths' not in swagger_spec:
        if verbose:
            log("Specification does not contain 'paths' key.", level="CRITICAL")
        return results

    unique_endpoints = set()
    all_results = []
    max_workers = min(100, os.cpu_count() * 5)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_endpoint = {}
        for path, methods in swagger_spec['paths'].items():
            if not methods:
                continue
            for mthd, details in methods.items():
                if mthd.lower() not in ['get','post','put','patch','delete']:
                    continue
                if mthd.upper() != 'GET' and not include_risk:
                    continue

                endpoint_key = (mthd.upper(), path)
                if endpoint_key in unique_endpoints:
                    continue
                unique_endpoints.add(endpoint_key)

                parameters = details.get('parameters', [])
                content_types = ['application/json']
                schema = None

                # If OpenAPI 3.x uses requestBody
                if 'requestBody' in details:
                    rb_content = details['requestBody'].get('content', {})
                    if not rb_content:
                        continue
                    content_types = list(rb_content.keys())
                    for ct in content_types:
                        schema = rb_content[ct].get('schema', {})
                        request_body = build_request_body(schema, ct)
                        fut = executor.submit(
                            test_endpoint,
                            base_url, headers, base_path, path, mthd,
                            parameters, request_body, ct,
                            verbose, rate, include_all,
                            product_mode=product_mode, brute=brute
                        )
                        future_to_endpoint[fut] = (mthd, path, ct)
                else:
                    # Swagger 2.0 with parameters
                    if parameters:
                        for param in parameters:
                            if param.get('in') == 'body' and 'schema' in param:
                                schema = param['schema']
                                break
                    request_body = build_request_body(schema, 'application/json')
                    fut = executor.submit(
                        test_endpoint,
                        base_url, headers, base_path, path, mthd,
                        parameters, request_body, 'application/json',
                        verbose, rate, include_all,
                        product_mode=product_mode, brute=brute
                    )
                    future_to_endpoint[fut] = (mthd, path, 'application/json')

        for future in as_completed(future_to_endpoint):
            mthd, pth, ct = future_to_endpoint[future]
            try:
                endpoint_results = future.result()
                if endpoint_results:
                    all_results.extend(endpoint_results)
            except Exception as exc:
                if verbose:
                    log(f"Endpoint {mthd.upper()} {pth} with content type {ct} generated an exception: {exc}", level="DEBUG")

    # Basepath fallback logic if 80%+ of responses are 404 with the same content length
    if not tried_basepath_fallback:
        num_responses = len(all_results)
        num_404s = sum(1 for r in all_results if r['status_code'] == 404)
        content_lengths = set(r['content_length'] for r in all_results if r['status_code'] == 404)
        if num_404s > 0 and num_responses > 0:
            proportion_404 = num_404s / num_responses
            if proportion_404 > 0.8 and len(content_lengths) == 1 and base_path != '/':
                if verbose:
                    log("Basepath fallback triggered. Retesting endpoints with basepath '/'.", level="INFO")
                all_results.clear()
                fallback = test_endpoints(
                    base_url, headers, '/', swagger_spec, verbose,
                    include_risk, include_all, product_mode=product_mode,
                    rate=rate, tried_basepath_fallback=True, brute=brute
                )
                return fallback

    return all_results

def fetch_swagger_spec(url, headers, verbose=False):
    """
    Attempts to fetch and parse an OpenAPI/Swagger spec from a given URL.
    Checks if response code is 200, content is JSON/YAML, and contains 'swagger'/'openapi'.
    Returns the parsed spec as a dictionary or None if unsuccessful.
    """
    if verbose:
        log(f"Fetching Swagger/OpenAPI spec directly from {url}", level="DEBUG")
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=TIMEOUT)
        ctype = resp.headers.get('Content-Type', '').lower()
        if resp.status_code == 200 and any(x in ctype for x in ['json','yaml','text/plain']):
            if 'swagger' in resp.text.lower() or 'openapi' in resp.text.lower():
                try:
                    if 'json' in ctype:
                        spec = resp.json()
                    else:
                        spec = yaml.safe_load(resp.text)
                    if verbose:
                        log("Successfully loaded spec.", level="SUCCESS")
                    return spec
                except (json.JSONDecodeError, yaml.YAMLError) as perr:
                    if verbose:
                        log(f"Error decoding spec from {url}: {perr}", level="DEBUG")
                        log(f"Failed to parse spec from {url}", level="DEBUG")
        else:
            if verbose:
                log(f"Invalid response from {url}: {resp.status_code}, Content-Type: {ctype}", level="WARNING")
                log(f"Failed to parse spec from {url}", level="DEBUG")
    except requests.exceptions.RequestException as e:
        if verbose:
            log(f"Error fetching Swagger/OpenAPI spec from {url}: {e}", level="DEBUG")
            log(f"Failed to parse spec from {url}", level="DEBUG")
    return None

def find_swagger_ui_docs(base_url, headers, verbose=False):
    """
    Attempts to detect a Swagger UI at known paths by scanning for references
    to swagger/openapi in the HTML or embedded JavaScript. If found, attempts
    to parse the discovered spec path or extract an embedded spec.
    """
    for pth in SWAGGER_UI_PATHS:
        swagger_ui_url = urljoin(base_url, pth)
        if verbose:
            log(f"Checking Swagger UI page at {swagger_ui_url}", level="DEBUG")
        try:
            r = requests.get(swagger_ui_url, headers=headers, verify=False, allow_redirects=False, timeout=TIMEOUT)
            if r.status_code == 200 and ('swagger' in r.text.lower() or 'openapi' in r.text.lower()):
                if verbose:
                    log(f"Swagger UI found at {swagger_ui_url}", level="DEBUG")
                spec_url = extract_spec_url_from_html(r.text)
                if spec_url:
                    full_spec_url = urljoin(swagger_ui_url, spec_url)
                    if verbose:
                        log(f"Found Swagger spec URL in HTML: {full_spec_url}", level="DEBUG")
                    if any(full_spec_url.lower().endswith(ext) for ext in ['.json', '.yaml', '.yml']):
                        sp = fetch_swagger_spec(full_spec_url, headers, verbose)
                        if sp:
                            return sp
                    else:
                        if verbose:
                            log(f"Spec URL does not have a valid spec extension: {full_spec_url}", level="DEBUG")
                        if full_spec_url.lower().endswith('.js'):
                            try:
                                js_r = requests.get(full_spec_url, headers=headers, verify=False, timeout=TIMEOUT)
                                if js_r.status_code == 200:
                                    if verbose:
                                        log(f"Attempting to extract embedded spec from JS file: {full_spec_url}", level="DEBUG")
                                    emb = extract_spec_from_js(js_r.text)
                                    if emb and isinstance(emb, dict):
                                        if verbose:
                                            log(f"Extracted embedded Swagger spec from JS file: {full_spec_url}", level="DEBUG")
                                        return emb
                            except requests.exceptions.RequestException as e:
                                if verbose:
                                    log(f"Error fetching JS file {full_spec_url}: {e}", level="DEBUG")
                js_files = re.findall(r'<script\s+src=["\']([^"\']+\.js)["\']', r.text, re.IGNORECASE)
                if verbose:
                    log(f"Found {len(js_files)} JavaScript files to analyze.", level="DEBUG")
                js_files = [x for x in js_files if is_local_js_file(x, swagger_ui_url)]
                if verbose:
                    log(f"{len(js_files)} JavaScript files are local and will be analyzed.", level="DEBUG")
                js_files_sorted = sorted(js_files, key=lambda x: 'init' in x.lower(), reverse=True)
                for jsf in js_files_sorted:
                    jsu = urljoin(swagger_ui_url, jsf)
                    if verbose:
                        log(f"Fetching JS file: {jsu}", level="DEBUG")
                    try:
                        js_resp = requests.get(jsu, headers=headers, verify=False, timeout=TIMEOUT)
                        if js_resp.status_code == 200:
                            spec_url_js = extract_spec_url_from_js(js_resp.text)
                            if spec_url_js:
                                full_spec_url_js = urljoin(jsu, spec_url_js)
                                if verbose:
                                    log(f"Found Swagger spec URL in JS: {full_spec_url_js}", level="DEBUG")
                                if any(full_spec_url_js.lower().endswith(ext) for ext in ['.json', '.yaml', '.yml']):
                                    sp2 = fetch_swagger_spec(full_spec_url_js, headers, verbose)
                                    if sp2:
                                        return sp2
                                else:
                                    if full_spec_url_js.lower().endswith('.js'):
                                        try:
                                            nested_js = requests.get(full_spec_url_js, headers=headers, verify=False, timeout=TIMEOUT)
                                            if nested_js.status_code == 200:
                                                emb2 = extract_spec_from_js(nested_js.text)
                                                if emb2 and isinstance(emb2, dict):
                                                    if verbose:
                                                        log(f"Extracted embedded Swagger spec from nested JS file: {full_spec_url_js}", level="DEBUG")
                                                    return emb2
                                        except requests.exceptions.RequestException as e:
                                            if verbose:
                                                log(f"Error fetching nested JS file {full_spec_url_js}: {e}", level="DEBUG")
                            emb = extract_spec_from_js(js_resp.text)
                            if emb and isinstance(emb, dict):
                                if verbose:
                                    log(f"Extracted embedded Swagger spec from JS file: {jsu}", level="DEBUG")
                                return emb
                    except requests.exceptions.RequestException as e:
                        if verbose:
                            log(f"Error fetching JS file {jsu}: {e}", level="DEBUG")
                spec_url_swash = extract_swashbuckle_config_spec_url(r.text)
                if spec_url_swash:
                    full_swash_url = urljoin(swagger_ui_url, spec_url_swash)
                    if verbose:
                        log(f"Found Swagger spec URL via swashbuckleConfig: {full_swash_url}", level="DEBUG")
                    sp3 = fetch_swagger_spec(full_swash_url, headers, verbose)
                    if sp3:
                        return sp3
        except requests.exceptions.RequestException as e:
            if verbose:
                log(f"Error checking Swagger UI page at {swagger_ui_url}: {e}", level="DEBUG")
    return None

def extract_swashbuckle_config_spec_url(html_text):
    """
    Extracts a discovery path from window.swashbuckleConfig in the HTML if it exists.
    Returns the string path or None.
    """
    match = re.search(r'window\.swashbuckleConfig\s*=\s*{([\s\S]*?)};', html_text)
    if match:
        config_content = match.group(1)
        disc_paths = re.findall(r'discoveryPaths\s*:\s*\[\s*["\']([^"\']+)["\']\s*\]', config_content)
        if disc_paths:
            return disc_paths[0]
    return None

def is_local_js_file(js_file_url, base_url):
    """
    Determines if a JS file reference is local by comparing netloc to base_url's netloc.
    """
    parsed_js = urlparse(js_file_url)
    parsed_base = urlparse(base_url)
    if not parsed_js.netloc or parsed_js.netloc == parsed_base.netloc:
        return True
    return False

def extract_spec_url_from_html(html_text):
    """
    Extracts a potential swagger spec URL from HTML content
    by searching for 'url: "..."' patterns or SwaggerUIBundle references.
    """
    matches = re.findall(r'url:\s*["\'](.*?)["\']', html_text)
    if matches:
        return matches[0]
    matches = re.findall(r'SwaggerUIBundle\s*\(\s*{\s*url:\s*"(.*?)"', html_text, re.DOTALL)
    if matches:
        return matches[0]
    soup = BeautifulSoup(html_text, 'html.parser')
    for script in soup.find_all('script'):
        sc = script.string
        if sc and 'url:' in sc:
            mm = re.findall(r'url:\s*"(.*?)"', sc)
            if mm:
                return mm[0]
    return None

def extract_spec_url_from_js(js_text):
    """
    Extracts a swagger spec URL from JavaScript code by searching for
    various patterns like 'url: "..."', 'urls:[ { url:"..." } ]', etc.
    """
    patterns = [
        r'url:\s*["\'](.*?)["\']',
        r'urls:\s*\[\s*{\s*url:\s*["\'](.*?)["\']',
        r'const\s+\w+\s*=\s*["\'](.*?)["\']',
        r'defaultDefinitionUrl\s*=\s*["\'](.*?)["\']',
        r'definitionURL\s*=\s*["\'](.*?)["\']',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text)
        if matches:
            return matches[0]
    return None

def extract_spec_from_js(js_text):
    """
    Attempts to extract an embedded swagger spec from a JavaScript file.
    Removes comments, looks for object definitions with braces, and tries
    to parse them as JSON after minor adjustments.
    """
    js_text = re.sub(r'/\*[\s\S]*?\*/', '', js_text)
    js_text = re.sub(r'//.*', '', js_text)

    patterns = [
        r'(?:var|let|const)\s+(\w+)\s*=\s*({[\s\S]*?});',
        r'(\w+)\s*=\s*({[\s\S]*?});',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text, re.DOTALL)
        for var_name, obj_str in matches:
            cleaned_str = js_object_to_json(obj_str)
            if cleaned_str:
                try:
                    spec = json.loads(cleaned_str)
                    return spec
                except json.JSONDecodeError:
                    continue
    return None

def js_object_to_json(js_object_str):
    """
    Converts a JavaScript object string into a valid JSON string by
    replacing single quotes, adding quotes to keys, and removing trailing commas.
    """
    try:
        js_object_str = js_object_str.strip()
        js_object_str = re.sub(r"'", r'"', js_object_str)
        js_object_str = re.sub(r'([{,]\s*)(\w+)\s*:', r'\1"\2":', js_object_str)
        js_object_str = re.sub(r',\s*([}\]])', r'\1', js_object_str)
        return js_object_str
    except Exception:
        return None

def process_input(urls):
    """
    Ensures each URL has a valid scheme (http or https).
    If not present, prepends https:// to the beginning.
    """
    processed = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        processed.append(url)
    return processed

def parse_header_argument(header):
    """
    Validate header passed from CLI as string eg:
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0
    """
    items = header.split(":")
    if len(items) < 2:
        raise argparse.ArgumentTypeError(f"Invalid header value: {header}, expecting key: value")

    key = items[0].strip()
    value = ':'.join(items[1:]).strip()
    return {key: value}

def main(urls, headers, verbose, include_risk, include_all, product_mode, stats_flag, rate, brute, json_output):
    """
    Main function controlling flow:
    1. Tracks start time
    2. Processes input URLs
    3. Creates concurrency for scanning each host
    4. Accumulates results
    5. Prints or outputs final results and stats
    """
    global SCAN_START_TIME, SCAN_END_TIME, TOTAL_REQUESTS
    SCAN_START_TIME = time.time()  # Start the timer

    all_results = []
    processed_urls = process_input(urls)
    results_lock = threading.Lock()

    stats = {
        "unique_hosts_provided": len(set(urlparse(u).netloc for u in processed_urls)),
        "active_hosts": 0,
        "hosts_with_valid_spec": 0,
        "hosts_with_valid_endpoint": 0,
        "hosts_with_pii": 0,
        "pii_detection_methods": set(),
        "percentage_hosts_with_endpoint": 0,
        "regexes_found": set()
    }

    def process_url(base_url):
        """
        Scans a single base_url to find a swagger spec using direct spec,
        swagger-ui detection, or known direct paths. If found, calls test_endpoints.
        Accumulates results and updates stats accordingly.
        """
        nonlocal all_results, stats
        parsed_input_url = urlparse(base_url)
        host = parsed_input_url.netloc

        with lock:
            stats["active_hosts"] += 1

        # Check if the URL might be a direct spec (ends with .json/.yaml/.yml)
        if any(base_url.lower().endswith(ext) for ext in ['.json', '.yaml', '.yml']):
            if not product_mode:
                log(f"Processing direct spec URL: {base_url}", level="INFO")
            swagger_spec = fetch_swagger_spec(base_url, headers, verbose)
            if swagger_spec:
                with lock:
                    stats["hosts_with_valid_spec"] += 1
                if not product_mode:
                    log("Successfully loaded spec.", level="INFO")
                base_path = '/'
                if 'servers' in swagger_spec and isinstance(swagger_spec['servers'], list) and swagger_spec['servers']:
                    base_path = swagger_spec['servers'][0].get('url', '/')
                elif 'basePath' in swagger_spec:
                    base_path = swagger_spec.get('basePath', '/')
                if not product_mode:
                    log("Scanning endpoints.", level="INFO")
                rslts = test_endpoints(
                    base_url, headers, base_path, swagger_spec,
                    verbose, include_risk, include_all,
                    product_mode=product_mode, rate=rate, brute=brute
                )
                del swagger_spec
                with results_lock:
                    all_results.extend(rslts)
                    if rslts:
                        stats["hosts_with_valid_endpoint"] += 1
                        for rr in rslts:
                            if rr['pii_detected']:
                                stats["hosts_with_pii"] += 1
                                stats["pii_detection_methods"].update(rr['pii_detection_methods'])
                                stats["regexes_found"].update(rr['regex_patterns_found'].values())
                return
            else:
                if verbose:
                    log(f"Failed to parse spec from {base_url}", level="DEBUG")
                with lock:
                    bad_hosts.add(host)
                return

        # Phase 1 & 2: Look for swagger UI
        swagger_spec = find_swagger_ui_docs(base_url, headers, verbose)
        if swagger_spec:
            with lock:
                stats["hosts_with_valid_spec"] += 1
            if not product_mode:
                log(f"Spec identified via Swagger-UI detection.", level="INFO")
            base_path = '/'
            if 'servers' in swagger_spec and isinstance(swagger_spec['servers'], list) and swagger_spec['servers']:
                base_path = swagger_spec['servers'][0].get('url', '/')
            elif 'basePath' in swagger_spec:
                base_path = swagger_spec.get('basePath', '/')
            if not product_mode:
                log("Scanning endpoints.", level="INFO")
            rslts = test_endpoints(
                base_url, headers, base_path, swagger_spec,
                verbose, include_risk, include_all,
                product_mode=product_mode, rate=rate, brute=brute
            )
            del swagger_spec
            with results_lock:
                all_results.extend(rslts)
                if rslts:
                    stats["hosts_with_valid_endpoint"] += 1
                    for rr in rslts:
                        if rr['pii_detected']:
                            stats["hosts_with_pii"] += 1
                            stats["pii_detection_methods"].update(rr['pii_detection_methods'])
                            stats["regexes_found"].update(rr['regex_patterns_found'].values())
            return

        # Phase 3: Direct spec path detection
        if verbose:
            log(f"Proceeding to Phase 3: Direct Spec Path Detection for {base_url}", level="DEBUG")
        for pth in DIRECT_SPEC_PATHS:
            spec_url = urljoin(base_url, pth)
            if verbose:
                log(f"Attempting to fetch spec from direct path: {spec_url}", level="DEBUG")
            sws = fetch_swagger_spec(spec_url, headers, verbose)
            if sws:
                with lock:
                    stats["hosts_with_valid_spec"] += 1
                if not product_mode:
                    log(f"Spec identified via direct path detection: {spec_url}", level="INFO")
                base_path = '/'
                if 'servers' in sws and isinstance(sws['servers'], list) and sws['servers']:
                    base_path = sws['servers'][0].get('url', '/')
                elif 'basePath' in sws:
                    base_path = sws.get('basePath', '/')
                if not product_mode:
                    log("Scanning endpoints.", level="INFO")
                rslts2 = test_endpoints(
                    base_url, headers, base_path, sws,
                    verbose, include_risk, include_all,
                    product_mode=product_mode, rate=rate, brute=brute
                )
                del sws
                with results_lock:
                    all_results.extend(rslts2)
                    if rslts2:
                        stats["hosts_with_valid_endpoint"] += 1
                        for rr in rslts2:
                            if rr['pii_detected']:
                                stats["hosts_with_pii"] += 1
                                stats["pii_detection_methods"].update(rr['pii_detection_methods'])
                                stats["regexes_found"].update(rr['regex_patterns_found'].values())
                return
        else:
            if verbose:
                log(f"No valid Swagger/OpenAPI spec found for {base_url}.", level="DEBUG")
                log(f"Failed to parse spec from {base_url}", level="DEBUG")
            else:
                log(f"No spec found for {base_url}.", level="INFO")
            with lock:
                bad_hosts.add(host)

    if not product_mode:
        print_banner()

    max_workers2 = min(100, os.cpu_count() * 5, len(processed_urls)) if len(processed_urls) > 0 else 1
    with ThreadPoolExecutor(max_workers=max_workers2) as executor:
        futs = {executor.submit(process_url, url): url for url in processed_urls}
        if not product_mode:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Processing URLs", total=len(futs))
                for fut in as_completed(futs):
                    u = futs[fut]
                    try:
                        fut.result()
                    except Exception as exc:
                        if verbose:
                            log(f"Error processing URL {u}: {exc}", level="DEBUG")
                    progress.update(task, advance=1)
        else:
            for fut in as_completed(futs):
                u = futs[fut]
                try:
                    fut.result()
                except Exception as exc:
                    if verbose:
                        log(f"Error processing URL {u}: {exc}", level="DEBUG")

    SCAN_END_TIME = time.time()  # End the timer
    scan_duration = SCAN_END_TIME - SCAN_START_TIME

    if stats["active_hosts"] > 0:
        stats["percentage_hosts_with_endpoint"] = round(
            (stats["hosts_with_valid_endpoint"] / stats["active_hosts"]) * 100, 2
        )
    else:
        stats["percentage_hosts_with_endpoint"] = 0.0

    stats["pii_detection_methods"] = list(stats["pii_detection_methods"])
    stats["regexes_found"] = list(stats["regexes_found"])

    # Add total requests + average requests per second
    stats["total_requests_sent"] = TOTAL_REQUESTS
    if scan_duration > 0:
        stats["average_requests_per_second"] = round(TOTAL_REQUESTS / scan_duration, 2)
    else:
        stats["average_requests_per_second"] = 0.0

    if product_mode:
        grouped_results = {}
        for r in all_results:
            if r['pii_detected'] or r['interesting_response']:
                key = (r['method'], r['path_template'])
                existing = grouped_results.get(key)
                if existing:
                    if r['content_length'] > existing['content_length']:
                        grouped_results[key] = r
                else:
                    grouped_results[key] = r

        final_results = list(grouped_results.values())
        final_results.sort(key=lambda x: (-x['content_length'], not x['pii_detected']))

        clean_final_results = []
        for r in final_results:
            clean_res = {kk: vv for kk, vv in r.items() if kk != 'path_template'}
            if not clean_res['body']:
                del clean_res['body']
            if 'pii_data' in clean_res and clean_res['pii_data']:
                clean_res['pii_data'] = clean_res['pii_data']
                clean_res['pii_detection_details'] = r['pii_detection_details']
            clean_final_results.append(clean_res)

        output = {"results": clean_final_results}
        if stats_flag:
            output["stats"] = stats
        console.print_json(data=output)
    else:
        grouped_results = {}
        for r in all_results:
            key = (r['method'], r['path_template'])
            existing = grouped_results.get(key)
            if existing:
                if r['content_length'] > existing['content_length']:
                    grouped_results[key] = r
            else:
                grouped_results[key] = r

        final_results = list(grouped_results.values())
        final_results.sort(key=lambda x: (-x['content_length'], not x['pii_detected']))

        if include_all:
            final_results = [
                rr for rr in final_results
                if rr['status_code'] not in [401, 403]
            ]
        else:
            final_results = [
                rr for rr in final_results
                if rr['status_code'] == 200
            ]

        if final_results:
            if json_output:
                out = {"results": final_results}
                if stats_flag:
                    out["stats"] = stats
                console.print_json(data=out)
            else:
                table = Table(title="API Endpoints", show_lines=False)
                table.add_column("Method", style="cyan", no_wrap=True)
                table.add_column("URL", style="magenta", overflow="fold")
                table.add_column("Status Code", style="green")
                table.add_column("Content Length", style="yellow")
                table.add_column("PII or Secret Detected", style="red")
                if include_risk:
                    table.add_column("Body", style="blue", overflow="fold")

                for rr in final_results:
                    pii_status = "Yes" if rr['pii_detected'] else "No"
                    row = [
                        rr['method'],
                        rr['url'],
                        str(rr['status_code']),
                        f"{rr['content_length']:,}",
                        pii_status
                    ]
                    if include_risk:
                        body_content = rr['body'] if rr['body'] else ""
                        row.append(body_content)
                    table.add_row(*row)

                console.print(table)
        else:
            log("No valid API responses found.", level="INFO")

        if stats_flag and not json_output:
            stats_table = Table(title="Scan Statistics", show_lines=False)
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="magenta")

            formatted_stats = stats.copy()
            formatted_stats["percentage_hosts_with_endpoint"] = f"{formatted_stats['percentage_hosts_with_endpoint']}%"
            formatted_stats["pii_detection_methods"] = ', '.join(formatted_stats["pii_detection_methods"])
            formatted_stats["regexes_found"] = ', '.join(formatted_stats["regexes_found"])

            for k, v in formatted_stats.items():
                if isinstance(v, float):
                    v = f"{v:.2f}"
                elif isinstance(v, int):
                    v = f"{v:,}"
                stats_table.add_row(k.replace('_',' ').title(), str(v))

            console.print(stats_table)

    # Writes any bad hosts to a file for reference
    if bad_hosts:
        bad_hosts_file = os.path.expanduser("~/.autoswagger/logs/bad-hosts.txt")
        os.makedirs(os.path.dirname(bad_hosts_file), exist_ok=True)
        with open(bad_hosts_file, 'a') as f:
            for host in bad_hosts:
                f.write(host + '\n')

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Autoswagger: Detect unauthenticated access control issues via Swagger/OpenAPI documentation.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example usage:\n  python autoswagger.py https://api.example.com -v "
    )
    parser.add_argument("urls", nargs="*", help="Base URL(s) or spec URL(s) of the target API(s)")
    parser.add_argument("-headers", type=parse_header_argument, default=[], action="extend", nargs='*',
                        help="Add custom headers")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-risk", action="store_true", help="Include non-GET requests in testing")
    parser.add_argument("-all", action="store_true", help="Include all HTTP status codes in the results, excluding 401 and 403")
    parser.add_argument("-product", action="store_true", help="Output all endpoints in JSON, flagging those that contain PII or have large responses.")
    parser.add_argument("-stats", action="store_true", help="Display scan statistics. Included in JSON if -product or -json is used.")
    parser.add_argument("-rate", type=int, default=30, help="Set the rate limit in requests per second (default: 30). Use 0 to disable rate limiting.")
    parser.add_argument("-b", "--brute", action="store_true", help="Enable exhaustive testing of parameter values.")
    parser.add_argument("-json", action="store_true", help="Output results in JSON format in default mode.")

    args = parser.parse_args()

    if not args.urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    else:
        urls = args.urls

    if not urls:
        print_banner()
        parser.print_help()
        sys.exit()

    # merge headers into one dict
    headers = {}
    for item in args.headers:
        headers.update(item)

    product_mode = args.product
    verbose = args.verbose
    include_risk = args.risk
    include_all = args.all
    stats_flag = args.stats
    rate = args.rate
    brute = args.brute
    json_output = args.json

    # Set up file logging if verbose is enabled
    if verbose:
        log_dir = os.path.expanduser("~/.autoswagger/logs")
        os.makedirs(log_dir, exist_ok=True)
        log_filename = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-log.txt")
        log_file_path = os.path.join(log_dir, log_filename)
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.propagate = False

    main(urls, headers, verbose, include_risk, include_all, product_mode, stats_flag, rate, brute, json_output)
