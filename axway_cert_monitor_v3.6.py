#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Axway Certificate Monitor v3.5 - Simplified JSON Output dengan Tabel Asli
Hanya menampilkan Expired, Critical, dan Warning certificates
Output JSON disederhanakan: hanya data per API
Output tabel dikembalikan ke format asli (per certificate)
Author: IT Team
"""

import ssl
import socket
import json
import datetime
import base64
import hashlib
import re
import sys
import os
import urllib.request
import urllib.error
from urllib.parse import urlparse
import argparse
import logging
import traceback
from collections import defaultdict

# ===== Konfigurasi =====
DEFAULT_APIM_HOST = "10.197.56.17"
DEFAULT_APIM_PORT = 8075
DEFAULT_USERNAME = "apiadmin"
DEFAULT_PASSWORD = "P@ssw0rdBD!"

# ===== Setup Logging =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AxwayCertificateMonitor:
    def __init__(self, host, port, username, password, verify_ssl=False, warning_days=30, critical_days=7):
        """
        Initialize Axway Certificate Monitor
        """
        self.host = host
        self.port = port
        self.base_url = "https://{}:{}/api/portal/v1.4".format(host, port)
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.warning_days = warning_days
        self.critical_days = critical_days
        self.proxies_data = []
        self.certificates_info = []
        
        # Create basic auth header
        auth_string = "{}:{}".format(username, password)
        self.auth_header = "Basic " + base64.b64encode(auth_string.encode()).decode()
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        if not verify_ssl:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def fetch_proxies_light(self):
        """
        Fetch proxies data from /api/portal/v1.4/proxies/light
        """
        url = "{}/proxies/light".format(self.base_url)
        
        try:
            logger.info("Fetching proxies from {}".format(url))
            
            # Create request
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            req.add_header("Authorization", self.auth_header)
            req.add_header("User-Agent", "Axway-Cert-Monitor/3.5")
            
            # Execute request
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=30) as response:
                data = response.read().decode('utf-8')
                self.proxies_data = json.loads(data)
                
                logger.info("Successfully fetched {} proxies".format(len(self.proxies_data)))
                return self.proxies_data
                
        except urllib.error.HTTPError as e:
            logger.error("HTTP Error {}: {}".format(e.code, e.reason))
            try:
                error_body = e.read().decode()
                logger.error("Response: {}".format(error_body))
            except:
                pass
            raise
        except urllib.error.URLError as e:
            logger.error("URL Error: {}".format(e.reason))
            raise
        except json.JSONDecodeError as e:
            logger.error("JSON Decode Error: {}".format(e))
            raise
        except Exception as e:
            logger.error("Unexpected error: {}".format(e))
            raise
    
    def extract_certificates_from_proxies(self):
        """
        Extract certificate information from proxies data
        Focus hanya pada CA certificates dari field caCerts
        """
        certificates = []
        
        if not self.proxies_data:
            logger.warning("No proxies data available")
            return certificates
        
        logger.info("Processing {} proxies for CA certificates...".format(len(self.proxies_data)))
        
        proxy_count = 0
        cert_count = 0
        
        for proxy in self.proxies_data:
            proxy_count += 1
            proxy_name = proxy.get('name', 'Unknown')
            proxy_id = proxy.get('id', 'Unknown')
            
            # Get basepath information dari serviceProfiles
            basepaths = self._extract_basepaths(proxy)
            
            # Extract from caCerts field
            if 'caCerts' in proxy and isinstance(proxy['caCerts'], list):
                for cert_data in proxy['caCerts']:
                    cert_count += 1
                    cert_info = self._parse_certificate_data(cert_data, proxy_name, proxy_id, basepaths)
                    if cert_info:
                        certificates.append(cert_info)
        
        logger.info("Processed {} proxies, found {} CA certificates".format(proxy_count, cert_count))
        return certificates
    
    def _extract_basepaths(self, proxy):
        """
        Extract basepaths dari serviceProfiles._default.basePath
        """
        basepaths = []
        
        # Extract basepaths dari serviceProfiles
        if 'serviceProfiles' in proxy and isinstance(proxy['serviceProfiles'], dict):
            service_profiles = proxy['serviceProfiles']
            
            # Check for _default profile
            if '_default' in service_profiles:
                default_profile = service_profiles['_default']
                if isinstance(default_profile, dict) and 'basePath' in default_profile:
                    basepath = default_profile.get('basePath', '')
                    if basepath:
                        basepaths.append(basepath)
            
            # Also check other profiles if they exist
            for profile_name, profile_data in service_profiles.items():
                if profile_name != '_default' and isinstance(profile_data, dict):
                    if 'basePath' in profile_data:
                        basepath = profile_data.get('basePath', '')
                        if basepath and basepath not in basepaths:
                            basepaths.append(basepath)
        
        # If no basepaths found in serviceProfiles, use the path field as fallback
        if not basepaths and 'path' in proxy:
            path = proxy.get('path', '')
            if path:
                basepaths.append(path)
        
        return basepaths
    
    def _parse_certificate_data(self, cert_data, proxy_name, proxy_id, basepaths):
        """Parse certificate data dari field caCerts"""
        try:
            # Extract certificate information
            name = cert_data.get('name', 'Unknown')
            subject = cert_data.get('subject', 'Unknown')
            issuer = cert_data.get('issuer', 'Unknown')
            
            # Parse dates
            not_valid_before_ms = cert_data.get('notValidBefore')
            not_valid_after_ms = cert_data.get('notValidAfter')
            
            if not_valid_before_ms is None or not_valid_after_ms is None:
                logger.warning("Certificate '{}' has missing date information".format(name[:50]))
                return None
            
            # Convert dari milliseconds ke datetime
            try:
                not_valid_before = datetime.datetime.fromtimestamp(not_valid_before_ms / 1000.0)
                not_valid_after = datetime.datetime.fromtimestamp(not_valid_after_ms / 1000.0)
            except Exception as e:
                logger.error("Error converting dates for cert '{}': {}".format(name[:50], e))
                return None
            
            # Calculate days remaining
            now = datetime.datetime.now()
            days_remaining = (not_valid_after - now).days
            
            # Get fingerprints
            sha1_fingerprint = cert_data.get('sha1Fingerprint', '')
            md5_fingerprint = cert_data.get('md5Fingerprint', '')
            
            # Determine status
            status = self._determine_status(days_remaining)
            
            # Extract CN from subject
            cn = self._extract_cn_from_subject(subject)
            
            cert_info = {
                'api_name': proxy_name,
                'proxy_id': proxy_id,
                'cert_name': name,
                'subject': subject,
                'cn': cn,
                'issuer': issuer,
                'not_valid_before': not_valid_before.isoformat(),
                'not_valid_after': not_valid_after.isoformat(),
                'not_valid_before_timestamp': not_valid_before_ms,
                'not_valid_after_timestamp': not_valid_after_ms,
                'days_remaining': days_remaining,
                'is_expired': days_remaining < 0,
                'sha1_fingerprint': sha1_fingerprint,
                'md5_fingerprint': md5_fingerprint,
                'status': status,
                'type': 'ca_cert',
                'expired_field': cert_data.get('expired', False),
                'inbound': cert_data.get('inbound', False),
                'outbound': cert_data.get('outbound', False),
                'basepaths': basepaths,
                'basepaths_string': ', '.join(basepaths) if basepaths else 'No basepath',
                'parsed_at': now.isoformat()
            }
            
            return cert_info
                
        except Exception as e:
            logger.error("Error parsing certificate data: {}".format(e))
            return None
    
    def _extract_cn_from_subject(self, subject):
        """Extract Common Name dari certificate subject"""
        try:
            if not isinstance(subject, str):
                return 'Unknown'
            
            # Pattern untuk extract CN
            patterns = [
                r'CN=([^,]+)',  # Standard format
                r'CN\s*=\s*([^,]+)',  # With spaces
                r'Common Name\s*[:=]\s*([^,]+)',  # English format
            ]
            
            for pattern in patterns:
                match = re.search(pattern, subject, re.IGNORECASE)
                if match:
                    cn_value = match.group(1).strip()
                    # Clean up the CN value
                    cn_value = re.sub(r'^\s*[\'"]?|[\'"]?\s*$', '', cn_value)
                    return cn_value
            
            # Jika tidak ditemukan CN, return subject truncated
            return subject[:50] + "..." if len(subject) > 50 else subject
            
        except Exception as e:
            logger.debug("Could not extract CN from subject '{}': {}".format(subject[:50], e))
            return 'Unknown'
    
    def _determine_status(self, days_remaining):
        """Determine certificate status berdasarkan hari tersisa"""
        if days_remaining < 0:
            return 'EXPIRED'
        elif days_remaining <= self.critical_days:
            return 'CRITICAL'
        elif days_remaining <= self.warning_days:
            return 'WARNING'
        else:
            return 'VALID'
    
    def monitor_all_certificates(self):
        """
        Main method untuk monitor semua certificates
        Hanya fokus pada CA certificates dari caCerts field
        """
        logger.info("Starting Axway Certificate Monitoring")
        logger.info("Warning threshold: {} days, Critical threshold: {} days".format(
            self.warning_days, self.critical_days))
        
        # Fetch proxies data
        try:
            proxies = self.fetch_proxies_light()
        except Exception as e:
            logger.error("Failed to fetch proxies: {}".format(e))
            return {
                'error': "Failed to fetch proxies: {}".format(e),
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        # Extract CA certificates dari proxies
        certificates = self.extract_certificates_from_proxies()
        
        if not certificates:
            logger.warning("No CA certificates found in proxies data")
            return {
                'message': 'No CA certificates found',
                'timestamp': datetime.datetime.now().isoformat(),
                'total_proxies': len(proxies),
                'total_certificates': 0
            }
        
        # Filter hanya certificates dengan status EXPIRED, CRITICAL, atau WARNING
        filtered_certificates = []
        for cert in certificates:
            status = cert.get('status', 'VALID')
            if status in ['EXPIRED', 'CRITICAL', 'WARNING']:
                filtered_certificates.append(cert)
        
        # Untuk output tabel - KEMBALI ke format asli
        # Group certificates by status untuk tabel output
        by_status = defaultdict(list)
        for cert in filtered_certificates:
            status = cert.get('status', 'VALID')
            by_status[status].append(cert)
        
        # Summary untuk tabel output
        summary = {
            'expired': len(by_status.get('EXPIRED', [])),
            'critical': len(by_status.get('CRITICAL', [])),
            'warning': len(by_status.get('WARNING', [])),
            'valid': len([c for c in certificates if c.get('status') == 'VALID']),
            'error': 0
        }
        
        # Untuk simplified JSON - grouping per API
        api_certificates = []
        api_map = {}
        
        for cert in filtered_certificates:
            api_name = cert.get('api_name')
            proxy_id = cert.get('proxy_id')
            
            if api_name not in api_map:
                api_map[api_name] = {
                    'api_name': api_name,
                    'proxy_id': proxy_id,
                    'basepaths_string': cert.get('basepaths_string'),
                    'certificates': []
                }
            
            # Tambahkan certificate info ke API
            cert_info = {
                'cn': cert.get('cn'),
                'status': cert.get('status'),
                'days_remaining': cert.get('days_remaining'),
                'not_valid_after': cert.get('not_valid_after'),
                'issuer': cert.get('issuer'),
                'subject': cert.get('subject'),
                'sha1_fingerprint': cert.get('sha1_fingerprint'),
                'md5_fingerprint': cert.get('md5_fingerprint'),
                'is_expired': cert.get('is_expired')
            }
            api_map[api_name]['certificates'].append(cert_info)
        
        # Convert map ke list untuk simplified JSON
        for api_info in api_map.values():
            # Sort certificates by status severity
            api_info['certificates'].sort(key=lambda x: (
                x.get('status') == 'EXPIRED',
                x.get('status') == 'CRITICAL',
                x.get('status') == 'WARNING',
                x.get('days_remaining', 9999)
            ))
            
            # Tambahkan count certificates
            api_info['cert_count'] = len(api_info['certificates'])
            
            # Tambahkan worst status
            if any(cert.get('status') == 'EXPIRED' for cert in api_info['certificates']):
                api_info['worst_status'] = 'EXPIRED'
            elif any(cert.get('status') == 'CRITICAL' for cert in api_info['certificates']):
                api_info['worst_status'] = 'CRITICAL'
            elif any(cert.get('status') == 'WARNING' for cert in api_info['certificates']):
                api_info['worst_status'] = 'WARNING'
            else:
                api_info['worst_status'] = 'VALID'
            
            api_certificates.append(api_info)
        
        # Sort APIs by worst status
        api_certificates.sort(key=lambda x: (
            x.get('worst_status') == 'EXPIRED',
            x.get('worst_status') == 'CRITICAL',
            x.get('worst_status') == 'WARNING',
            x.get('api_name')
        ))
        
        # Results untuk semua output
        results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'axway_host': self.host,
            'total_proxies': len(proxies),
            'total_certificates': len(certificates),
            'total_problem_certificates': len(filtered_certificates),
            'total_apis_with_problems': len(api_certificates),
            
            # Data untuk output tabel (format asli)
            'summary': summary,
            'by_status': dict(by_status),
            
            # Data untuk simplified JSON
            'apis': api_certificates,
            
            # Data original untuk compatibility
            'certificates': certificates
        }
        
        logger.info("Certificate monitoring completed")
        logger.info("Summary: Expired={}, Critical={}, Warning={}".format(
            summary['expired'], summary['critical'], summary['warning']))
        
        return results
    
    def generate_solarwinds_output(self, results):
        """
        Generate output untuk SolarWinds SAM
        """
        output_lines = []
        
        # Jika ada error di results
        if 'error' in results:
            output_lines.append("Statistic.WaitingPartnerUpdate: 0")
            output_lines.append("Message.WaitingPartnerUpdate: API Error: {}".format(results['error'][:100]))
            output_lines.append("Statistic.ReadyForUpdate: 0")
            output_lines.append("Message.ReadyForUpdate: -")
            output_lines.append("Statistic.HandshakeErrors: 1")
            output_lines.append("Message.HandshakeErrors: Failed to fetch data")
            output_lines.append("Statistic.OverallStatus: 2")
            return '\n'.join(output_lines), 2
        
        # Jika tidak ada certificates
        if 'total_problem_certificates' in results and results['total_problem_certificates'] == 0:
            output_lines.append("Statistic.WaitingPartnerUpdate: 0")
            output_lines.append("Message.WaitingPartnerUpdate: No certificates with problems")
            output_lines.append("Statistic.ReadyForUpdate: 0")
            output_lines.append("Message.ReadyForUpdate: -")
            output_lines.append("Statistic.HandshakeErrors: 0")
            output_lines.append("Message.HandshakeErrors: -")
            output_lines.append("Statistic.TotalProxies: {}".format(results.get('total_proxies', 0)))
            output_lines.append("Statistic.TotalCertificates: {}".format(results.get('total_certificates', 0)))
            output_lines.append("Statistic.OverallStatus: 0")
            return '\n'.join(output_lines), 0
        
        # Prepare counts (gunakan data dari summary)
        waiting_count = results['summary']['expired'] + results['summary']['critical']
        ready_count = results['summary']['warning']
        
        # Collect messages dari certificates by status
        waiting_messages = []
        ready_messages = []
        
        # Collect expired and critical certificates
        for status in ['EXPIRED', 'CRITICAL']:
            if status in results['by_status']:
                for cert in results['by_status'][status]:
                    cn = cert.get('cn', 'Unknown Certificate')
                    days = cert.get('days_remaining', 0)
                    waiting_messages.append("{} ({}d)".format(cn[:30], abs(days)))
        
        # Collect warning certificates
        if 'WARNING' in results['by_status']:
            for cert in results['by_status']['WARNING']:
                cn = cert.get('cn', 'Unknown Certificate')
                days = cert.get('days_remaining', 0)
                ready_messages.append("{} ({}d)".format(cn[:30], days))
        
        # Format output untuk SolarWinds
        output_lines.append("Statistic.WaitingPartnerUpdate: {}".format(waiting_count))
        waiting_msg = ", ".join(waiting_messages[:5]) if waiting_messages else "-"
        output_lines.append("Message.WaitingPartnerUpdate: {}".format(waiting_msg))
        
        output_lines.append("Statistic.ReadyForUpdate: {}".format(ready_count))
        ready_msg = ", ".join(ready_messages[:5]) if ready_messages else "-"
        output_lines.append("Message.ReadyForUpdate: {}".format(ready_msg))
        
        output_lines.append("Statistic.HandshakeErrors: 0")
        output_lines.append("Message.HandshakeErrors: -")
        
        # Additional statistics
        output_lines.append("Statistic.TotalProxies: {}".format(results['total_proxies']))
        output_lines.append("Statistic.TotalCertificates: {}".format(results['total_certificates']))
        output_lines.append("Statistic.ProblemCertificates: {}".format(results['total_problem_certificates']))
        
        # Determine exit code
        if results['summary']['expired'] > 0:
            exit_code = 2  # Critical
        elif results['summary']['critical'] > 0 or results['summary']['warning'] > 0:
            exit_code = 1  # Warning
        else:
            exit_code = 0  # OK
        
        output_lines.append("Statistic.OverallStatus: {}".format(exit_code))
        
        return '\n'.join(output_lines), exit_code
    
    def generate_table_output(self, results):
        """Generate output dalam bentuk tabel - Format ASLI (v3.4) dengan CN unik"""
        output = []
        
        # Header
        output.append("=" * 120)
        output.append("AXWAY CERTIFICATE MONITORING REPORT - {}".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        output.append("=" * 120)
        output.append("")
        
        # Summary Statistics - SAMA dengan v3.4
        output.append("📊 SUMMARY STATISTICS")
        output.append("-" * 120)
        output.append("Total APIs:        {:>4}    |    Total Certificates: {:>4}".format(
            results['total_proxies'], results['total_certificates']))
        output.append("Unique Cert CNs:   {:>4}    |    Expired:            {:>4}".format(
            results['total_apis_with_problems'], results['summary']['expired']))
        output.append("Critical (<{}d):    {:>4}    |    Warning (<{}d):     {:>4}".format(
            self.critical_days, results['summary']['critical'], self.warning_days, results['summary']['warning']))
        output.append("")
        
        # Helper function untuk menggabungkan certificates dengan CN yang sama
        def group_certificates_by_cn(certificates):
            """Group certificates by CN and combine basepaths"""
            grouped = {}
            
            for cert in certificates:
                cn = cert.get('cn', 'Unknown')
                days_remaining = cert.get('days_remaining', 0)
                expiry_date = cert.get('not_valid_after', 'N/A')
                
                # Format expiry date
                if expiry_date != 'N/A':
                    try:
                        expiry_dt = datetime.datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                        expiry_date_formatted = expiry_dt.strftime("%Y-%m-%d")
                    except:
                        expiry_date_formatted = expiry_date[:10]
                else:
                    expiry_date_formatted = 'N/A'
                
                basepaths = cert.get('basepaths', [])
                
                if cn not in grouped:
                    grouped[cn] = {
                        'cn': cn,
                        'days_remaining': days_remaining,
                        'expiry_date': expiry_date_formatted,
                        'basepaths_set': set(basepaths),
                        'raw_certificates': [cert]
                    }
                else:
                    # Tambahkan basepaths ke set
                    grouped[cn]['basepaths_set'].update(basepaths)
                    # Simpan certificate dengan days_remaining terkecil
                    if days_remaining < grouped[cn]['days_remaining']:
                        grouped[cn]['days_remaining'] = days_remaining
                    # Keep raw certificates
                    grouped[cn]['raw_certificates'].append(cert)
            
            # Konversi ke list dan format basepaths
            result = []
            for cn, data in grouped.items():
                # Gabungkan basepaths menjadi string
                basepaths_list = sorted(list(data['basepaths_set']))
                basepaths_string = ', '.join(basepaths_list)
                
                result.append({
                    'cn': data['cn'],
                    'days_remaining': data['days_remaining'],
                    'expiry_date': data['expiry_date'],
                    'basepaths_string': basepaths_string,
                    'raw_certificates': data['raw_certificates']
                })
            
            # Sort by days_remaining
            result.sort(key=lambda x: x['days_remaining'])
            return result
        
        # Expired Certificates Table - TAMPILKAN DENGAN CN UNIK
        expired_certs = results['by_status'].get('EXPIRED', [])
        if expired_certs:
            output.append("🔴 EXPIRED CERTIFICATES")
            output.append("-" * 120)
            
            # Group certificates by CN
            grouped_expired = group_certificates_by_cn(expired_certs)
            
            # Create table header
            output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                "No", "CN Certificate", "Days Expired", "Expiry Date", "Basepath"))
            output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                "-"*5, "-"*35, "-"*15, "-"*20, "-"*45))
            
            for idx, cert in enumerate(grouped_expired, 1):
                cn = cert.get('cn', 'Unknown')
                days_expired = abs(cert.get('days_remaining', 0))
                expiry_date = cert.get('expiry_date', 'N/A')
                basepath = cert.get('basepaths_string', 'No basepath')
                
                # Truncate long CN names
                cn_display = cn[:35] + "..." if len(cn) > 35 else cn
                basepath_display = basepath[:45] + "..." if len(basepath) > 45 else basepath
                
                output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                    idx, 
                    cn_display, 
                    "{} days".format(days_expired),
                    expiry_date[:20],
                    basepath_display
                ))
            output.append("")
        
        # Critical Certificates Table - TAMPILKAN DENGAN CN UNIK
        critical_certs = results['by_status'].get('CRITICAL', [])
        if critical_certs:
            output.append("🟠 CRITICAL CERTIFICATES (Expiring in ≤ {} days)".format(self.critical_days))
            output.append("-" * 120)
            
            # Group certificates by CN
            grouped_critical = group_certificates_by_cn(critical_certs)
            
            output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                "No", "CN Certificate", "Days Left", "Expiry Date", "Basepath"))
            output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                "-"*5, "-"*35, "-"*15, "-"*20, "-"*45))
            
            for idx, cert in enumerate(grouped_critical, 1):
                cn = cert.get('cn', 'Unknown')
                days_left = cert.get('days_remaining', 0)
                expiry_date = cert.get('expiry_date', 'N/A')
                basepath = cert.get('basepaths_string', 'No basepath')
                
                # Truncate long CN names
                cn_display = cn[:35] + "..." if len(cn) > 35 else cn
                basepath_display = basepath[:45] + "..." if len(basepath) > 45 else basepath
                
                output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                    idx, 
                    cn_display, 
                    "{} days".format(days_left),
                    expiry_date[:20],
                    basepath_display
                ))
            output.append("")
        
        # Warning Certificates Table - TAMPILKAN DENGAN CN UNIK
        warning_certs = results['by_status'].get('WARNING', [])
        if warning_certs:
            output.append("🟡 WARNING CERTIFICATES (Expiring in ≤ {} days)".format(self.warning_days))
            output.append("-" * 120)
            
            # Group certificates by CN
            grouped_warning = group_certificates_by_cn(warning_certs)
            
            output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                "No", "CN Certificate", "Days Left", "Expiry Date", "Basepath"))
            output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                "-"*5, "-"*35, "-"*15, "-"*20, "-"*45))
            
            for idx, cert in enumerate(grouped_warning, 1):
                cn = cert.get('cn', 'Unknown')
                days_left = cert.get('days_remaining', 0)
                expiry_date = cert.get('expiry_date', 'N/A')
                basepath = cert.get('basepaths_string', 'No basepath')
                
                # Truncate long CN names
                cn_display = cn[:35] + "..." if len(cn) > 35 else cn
                basepath_display = basepath[:45] + "..." if len(basepath) > 45 else basepath
                
                output.append("{:<5} {:<35} {:<15} {:<20} {:<45}".format(
                    idx, 
                    cn_display, 
                    "{} days".format(days_left),
                    expiry_date[:20],
                    basepath_display
                ))
            output.append("")
        
        # Footer
        output.append("=" * 120)
        output.append("Generated by Axway Certificate Monitor v3.5")
        output.append("=" * 120)
        
        return '\n'.join(output)
    
    def generate_simplified_json(self, results):
        """
        Generate simplified JSON output tanpa summary atau cert_list
        """
        if 'error' in results:
            return json.dumps({
                'error': results['error'],
                'timestamp': results['timestamp']
            }, indent=2, ensure_ascii=False, default=str)
        
        # Buat output sederhana
        simplified = {
            'timestamp': results['timestamp'],
            'axway_host': results['axway_host'],
            'total_proxies': results['total_proxies'],
            'total_certificates': results['total_certificates'],
            'total_problem_certificates': results['total_problem_certificates'],
            'total_apis_with_problems': results['total_apis_with_problems'],
            'apis': []
        }
        
        # Tambahkan data API sederhana
        for api in results.get('apis', []):
            simple_api = {
                'api_name': api.get('api_name'),
                'proxy_id': api.get('proxy_id'),
                'basepaths_string': api.get('basepaths_string'),
                'worst_status': api.get('worst_status'),
                'cert_count': api.get('cert_count'),
                'certificates': []
            }
            
            # Tambahkan certificates sederhana
            for cert in api.get('certificates', []):
                simple_cert = {
                    'cn': cert.get('cn'),
                    'status': cert.get('status'),
                    'days_remaining': cert.get('days_remaining'),
                    'not_valid_after': cert.get('not_valid_after'),
                    'issuer': cert.get('issuer'),
                    'subject': cert.get('subject'),
                    'sha1_fingerprint': cert.get('sha1_fingerprint'),
                    'md5_fingerprint': cert.get('md5_fingerprint'),
                    'is_expired': cert.get('is_expired')
                }
                simple_api['certificates'].append(simple_cert)
            
            simplified['apis'].append(simple_api)
        
        return json.dumps(simplified, indent=2, ensure_ascii=False, default=str)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Axway CA Certificate Monitor for SolarWinds')
    parser.add_argument('--host', default=DEFAULT_APIM_HOST,
                        help='Axway API Manager host')
    parser.add_argument('--port', type=int, default=DEFAULT_APIM_PORT,
                        help='Axway API port')
    parser.add_argument('--username', default=DEFAULT_USERNAME,
                        help='API username')
    parser.add_argument('--password', default=DEFAULT_PASSWORD,
                        help='API password')
    parser.add_argument('--warning-days', type=int, default=30,
                        help='Days before expiry for warning status')
    parser.add_argument('--critical-days', type=int, default=7,
                        help='Days before expiry for critical status')
    parser.add_argument('--output-file', help='Save results to JSON file')
    parser.add_argument('--simple-json-file', help='Save simplified JSON to file')
    parser.add_argument('--report-file', help='Save detailed report to file')
    parser.add_argument('--table-file', help='Save table output to file')
    parser.add_argument('--verify-ssl', action='store_true',
                        help='Verify SSL certificates')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--table', '-t', action='store_true',
                        help='Display output in table format')
    parser.add_argument('--simple-json', '-s', action='store_true',
                        help='Display simplified JSON output')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    
    try:
        # Initialize monitor
        monitor = AxwayCertificateMonitor(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            verify_ssl=args.verify_ssl,
            warning_days=args.warning_days,
            critical_days=args.critical_days
        )
        
        # Run monitoring
        results = monitor.monitor_all_certificates()
        
        # Generate SolarWinds output
        solarwinds_output, exit_code = monitor.generate_solarwinds_output(results)
        
        # Print SolarWinds output (untuk automation)
        print(solarwinds_output)
        
        # Generate simplified JSON jika diminta
        if args.simple_json:
            simple_json = monitor.generate_simplified_json(results)
            print("\n" + simple_json)
        
        # Generate and display table output jika diminta (FORMAT ASLI)
        if args.table:
            table_output = monitor.generate_table_output(results)
            print("\n" + table_output)
        
        # Save to files jika diminta
        if args.output_file:
            with open(args.output_file, 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            logger.info("Full results saved to {}".format(args.output_file))
        
        if args.simple_json_file:
            simple_json = monitor.generate_simplified_json(results)
            with open(args.simple_json_file, 'w', encoding='utf-8') as f:
                f.write(simple_json)
            logger.info("Simplified JSON saved to {}".format(args.simple_json_file))
        
        if args.report_file and args.table:
            table_output = monitor.generate_table_output(results)
            with open(args.report_file, 'w', encoding='utf-8') as f:
                f.write(table_output)
            logger.info("Table report saved to {}".format(args.report_file))
        
        if args.table_file and args.table:
            table_output = monitor.generate_table_output(results)
            with open(args.table_file, 'w', encoding='utf-8') as f:
                f.write(table_output)
            logger.info("Table output saved to {}".format(args.table_file))
        
        # Exit dengan code yang sesuai
        sys.exit(exit_code)
        
    except Exception as e:
        logger.error("Fatal error: {}".format(e))
        if args.debug:
            logger.error(traceback.format_exc())
        
        print("Statistic.WaitingPartnerUpdate: 0")
        print("Message.WaitingPartnerUpdate: Script error: {}".format(str(e)[:100]))
        print("Statistic.ReadyForUpdate: 0")
        print("Message.ReadyForUpdate: -")
        print("Statistic.HandshakeErrors: 1")
        print("Message.HandshakeErrors: Script execution failed")
        print("Statistic.OverallStatus: 2")
        sys.exit(2)


if __name__ == "__main__":
    main()
