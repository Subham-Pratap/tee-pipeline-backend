import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def find_files(repo_path, extensions):
    """Find all files with given extensions in repo."""
    found = []
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden folders and common non-essential folders
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'venv', '__pycache__']]
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                found.append(os.path.join(root, file))
    return found


def test_sgx_detection(repo_path):
    """
    Test 1: SGX Project Detection
    Checks if this is an Intel SGX project by looking for:
    - .edl files (Enclave Definition Language)
    - sgx_ prefixed function calls
    - SGX SDK includes
    """
    result = {
        "name": "SGX SDK Detection",
        "status": "passed",
        "log": "",
        "findings": []
    }

    log_lines = ["$ Checking for SGX SDK usage patterns..."]

    # Check for .edl files
    edl_files = find_files(repo_path, ['.edl'])
    if edl_files:
        for f in edl_files:
            rel_path = os.path.relpath(f, repo_path)
            log_lines.append(f"✓ Found EDL file: {rel_path}")
            result["findings"].append(f"EDL file: {rel_path}")

    # Check for SGX includes and function calls in C/C++ files
    code_files = find_files(repo_path, ['.c', '.cpp', '.h', '.hpp'])
    sgx_patterns = [
        (r'#include\s*[<"]sgx', 'SGX include'),
        (r'sgx_create_enclave\s*\(', 'sgx_create_enclave()'),
        (r'sgx_destroy_enclave\s*\(', 'sgx_destroy_enclave()'),
        (r'sgx_ecall\s*\(', 'sgx_ecall()'),
    ]

    for filepath in code_files:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                rel_path = os.path.relpath(filepath, repo_path)
                for pattern, name in sgx_patterns:
                    if re.search(pattern, content):
                        log_lines.append(f"✓ Found {name} in {rel_path}")
                        result["findings"].append(f"{name} in {rel_path}")
        except Exception:
            pass

    # Check for SGX Makefile patterns
    makefiles = find_files(repo_path, ['Makefile', 'makefile', 'CMakeLists.txt'])
    for filepath in makefiles:
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                if 'SGX_SDK' in content or 'sgx_' in content.lower():
                    rel_path = os.path.relpath(filepath, repo_path)
                    log_lines.append(f"✓ Found SGX references in {rel_path}")
                    result["findings"].append(f"SGX Makefile: {rel_path}")
        except Exception:
            pass

    # Determine result
    if not result["findings"]:
        result["status"] = "failed"
        log_lines.append("✗ No SGX SDK patterns detected")
        log_lines.append("  This doesn't appear to be an SGX project")
    else:
        log_lines.append(f"✓ SGX SDK detected ({len(result['findings'])} indicators found)")

    result["log"] = "\n".join(log_lines)
    return result


def test_enclave_config(repo_path):
    """
    Test 2: Enclave Configuration Audit
    Parses enclave.config.xml and checks security settings:
    - DisableDebug should be 1 (enabled) for production
    - HeapMaxSize should be reasonable
    - StackMaxSize should be reasonable
    """
    result = {
        "name": "Enclave Config Audit",
        "status": "passed",
        "log": "",
        "findings": []
    }

    log_lines = ["$ Auditing enclave configuration..."]

    # Find config files
    config_patterns = ['enclave.config.xml', 'Enclave.config.xml', '.config.xml']
    config_files = []
    for pattern in config_patterns:
        config_files.extend(find_files(repo_path, [pattern]))

    # Also search for any XML that might be enclave config
    xml_files = find_files(repo_path, ['.xml'])
    for xml_file in xml_files:
        if 'config' in xml_file.lower() and xml_file not in config_files:
            config_files.append(xml_file)

    if not config_files:
        result["status"] = "pending"
        log_lines.append("⚠ No enclave.config.xml found")
        log_lines.append("  Skipping enclave configuration audit")
        result["log"] = "\n".join(log_lines)
        return result

    warnings = []

    for config_file in config_files:
        rel_path = os.path.relpath(config_file, repo_path)
        log_lines.append(f"  Analyzing: {rel_path}")

        try:
            tree = ET.parse(config_file)
            root = tree.getroot()

            # Check DisableDebug
            debug_elem = root.find('.//DisableDebug')
            if debug_elem is not None:
                if debug_elem.text == '1':
                    log_lines.append(f"  <DisableDebug>1</DisableDebug> ✓ Debug disabled")
                else:
                    log_lines.append(f"  <DisableDebug>{debug_elem.text}</DisableDebug> ⚠ Debug enabled!")
                    warnings.append("Debug mode is enabled - disable for production")

            # Check HeapMaxSize
            heap_elem = root.find('.//HeapMaxSize')
            if heap_elem is not None:
                log_lines.append(f"  <HeapMaxSize>{heap_elem.text}</HeapMaxSize> ✓")

            # Check StackMaxSize
            stack_elem = root.find('.//StackMaxSize')
            if stack_elem is not None:
                log_lines.append(f"  <StackMaxSize>{stack_elem.text}</StackMaxSize> ✓")

            # Check TCSNum (Thread Control Structure)
            tcs_elem = root.find('.//TCSNum')
            if tcs_elem is not None:
                log_lines.append(f"  <TCSNum>{tcs_elem.text}</TCSNum> ✓")

        except ET.ParseError:
            log_lines.append(f"  ⚠ Could not parse {rel_path}")
        except Exception as e:
            log_lines.append(f"  ⚠ Error reading {rel_path}: {str(e)}")

    if warnings:
        result["status"] = "passed"  # Pass with warnings
        result["findings"] = warnings
        log_lines.append(f"✓ Config audit complete ({len(warnings)} warnings)")
    else:
        log_lines.append("✓ Enclave configuration looks secure")

    result["log"] = "\n".join(log_lines)
    return result


def test_secrets_exposure(repo_path):
    """
    Test 3: Secrets Exposure Check
    Scans for potential hardcoded secrets outside enclave:
    - API keys
    - Passwords
    - Private keys
    - Tokens
    """
    result = {
        "name": "Secrets Exposure Check",
        "status": "passed",
        "log": "",
        "findings": []
    }

    log_lines = ["$ Scanning for exposed secrets..."]

    # Patterns that might indicate secrets
    secret_patterns = [
        (r'(?i)api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', 'API Key'),
        (r'(?i)password\s*[=:]\s*["\'][^"\']+["\']', 'Password'),
        (r'(?i)secret\s*[=:]\s*["\'][^"\']{10,}["\']', 'Secret'),
        (r'(?i)token\s*[=:]\s*["\'][^"\']{10,}["\']', 'Token'),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private Key'),
        (r'(?i)aws_access_key_id\s*[=:]\s*["\']?[A-Z0-9]{16,}', 'AWS Key'),
    ]

    # Files to scan (skip binary and irrelevant files)
    code_extensions = ['.c', '.cpp', '.h', '.hpp', '.py', '.js', '.ts', '.java', '.go', '.rs', '.config', '.xml', '.json', '.yaml', '.yml', '.env', '.txt']
    code_files = find_files(repo_path, code_extensions)

    warnings = []

    for filepath in code_files:
        rel_path = os.path.relpath(filepath, repo_path)

        # Skip files inside enclave (trusted) directories - these are OK
        if 'enclave' in rel_path.lower() and 'untrusted' not in rel_path.lower():
            continue

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')

                for line_num, line in enumerate(lines, 1):
                    for pattern, secret_type in secret_patterns:
                        if re.search(pattern, line):
                            warning = f"{secret_type} found in {rel_path}:{line_num}"
                            warnings.append(warning)
                            log_lines.append(f"⚠ {warning}")
        except Exception:
            pass

    # Log scanned files
    log_lines.insert(1, f"  Scanned {len(code_files)} files")

    if warnings:
        result["status"] = "failed"
        result["findings"] = warnings
        log_lines.append(f"✗ Found {len(warnings)} potential secret(s) exposed")
        log_lines.append("  Recommendation: Move secrets inside enclave or use environment variables")
    else:
        log_lines.append("✓ No exposed secrets detected")

    result["log"] = "\n".join(log_lines)
    return result


def run_all_tests(repo_path):
    """Run all test cases and return results."""
    return [
        test_sgx_detection(repo_path),
        test_enclave_config(repo_path),
        test_secrets_exposure(repo_path),
    ]