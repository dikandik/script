#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Axway Certificate Monitor v3.1 - No Valid Certificates Table
Hanya menampilkan Expired, Critical, dan Warning certificates
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
            req.add_header("User-Agent", "Axway-Cert-Monitor/3.1")
            
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
            
            # Extract from caCerts field
            if 'caCerts' in proxy and isinstance(proxy['caCerts'], list):
                for cert_data in proxy['caCerts']:
                    cert_count += 1
                    cert_info = self._parse_certificate_data(cert_data, proxy_name, proxy_id)
                    if cert_info:
                        certificates.append(cert_info)
        
        logger.info("Processed {} proxies, found {} CA certificates".format(proxy_count, cert_count))
        return certificates
    
    def _parse_certificate_data(self, cert_data, proxy_name, proxy_id):
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
        
        # Prepare results
        results = {
            'timestamp': datetime.datetime.now().isoformat(),
            'axway_host': self.host,
            'total_proxies': len(proxies),
            'total_certificates': len(certificates),
            'certificates': certificates,
            'summary': {
                'expired': 0,
                'critical': 0,
                'warning': 0,
                'valid': 0,
                'error': 0
            },
            'by_status': defaultdict(list)
        }
        
        # Update summary dan group data
        for cert in certificates:
            status = cert.get('status', 'ERROR')
            
            # Update summary counts
            if status == 'EXPIRED':
                results['summary']['expired'] += 1
            elif status == 'CRITICAL':
                results['summary']['critical'] += 1
            elif status == 'WARNING':
                results['summary']['warning'] += 1
            elif status == 'VALID':
                results['summary']['valid'] += 1
            elif status == 'ERROR':
                results['summary']['error'] += 1
            
            # Group by status
            results['by_status'][status].append(cert)
        
        logger.info("Certificate monitoring completed")
        logger.info("Summary: Expired={}, Critical={}, Warning={}, Valid={}".format(
            results['summary']['expired'],
            results['summary']['critical'],
            results['summary']['warning'],
            results['summary']['valid']
        ))
        
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
        if 'total_certificates' in results and results['total_certificates'] == 0:
            output_lines.append("Statistic.WaitingPartnerUpdate: 0")
            output_lines.append("Message.WaitingPartnerUpdate: No certificates found")
            output_lines.append("Statistic.ReadyForUpdate: 0")
            output_lines.append("Message.ReadyForUpdate: -")
            output_lines.append("Statistic.HandshakeErrors: 0")
            output_lines.append("Message.HandshakeErrors: -")
            output_lines.append("Statistic.TotalProxies: {}".format(results.get('total_proxies', 0)))
            output_lines.append("Statistic.TotalCertificates: 0")
            output_lines.append("Statistic.OverallStatus: 0")
            return '\n'.join(output_lines), 0
        
        # Prepare counts
        waiting_count = results['summary']['expired'] + results['summary']['critical']
        ready_count = results['summary']['warning']
        
        # Collect messages
        waiting_messages = []
        ready_messages = []
        
        for cert in results['certificates']:
            cn = cert.get('cn', 'Unknown Certificate')
            api_name = cert.get('api_name', 'Unknown API')
            days = cert.get('days_remaining', 0)
            status = cert.get('status', 'UNKNOWN')
            
            if status in ['EXPIRED', 'CRITICAL']:
                waiting_messages.append(
                    "{} ({}: {}d)".format(cn, api_name, abs(days)))
            elif status == 'WARNING':
                ready_messages.append(
                    "{} ({}: {}d)".format(cn, api_name, days))
        
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
        """Generate output dalam bentuk tabel - HANYA Expired, Critical, dan Warning"""
        output = []
        
        # Header
        output.append("=" * 100)
        output.append("AXWAY CERTIFICATE MONITORING REPORT - {}".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        output.append("=" * 100)
        output.append("")
        
        # Summary Statistics
        output.append("📊 SUMMARY STATISTICS")
        output.append("-" * 100)
        output.append("Total APIs:        {:>4}    |    Total Certificates: {:>4}".format(
            results['total_proxies'], results['total_certificates']))
        output.append("Expired:           {:>4}    |    Critical (<{}d):     {:>4}".format(
            results['summary']['expired'], self.critical_days, results['summary']['critical']))
        output.append("Warning (<{}d):    {:>4}    |    Valid:              {:>4}".format(
            self.warning_days, results['summary']['warning'], results['summary']['valid']))
        output.append("")
        
        # Expired Certificates Table - TAMPILKAN SEMUA
        expired_certs = results['by_status'].get('EXPIRED', [])
        if expired_certs:
            output.append("🔴 EXPIRED CERTIFICATES")
            output.append("-" * 100)
            
            # Create table header
            output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                "No", "CN Certificate", "API Name", "Days Expired", "Expiry Date"))
            output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                "-"*5, "-"*30, "-"*25, "-"*15, "-"*20))
            
            # Sort by days expired (most expired first)
            expired_certs_sorted = sorted(expired_certs, key=lambda x: x.get('days_remaining', 0))
            
            for idx, cert in enumerate(expired_certs_sorted, 1):
                cn = cert.get('cn', 'Unknown')
                api_name = cert.get('api_name', 'Unknown API')[:25]
                days_expired = abs(cert.get('days_remaining', 0))
                expiry_date = cert.get('not_valid_after', 'N/A')
                
                # Format expiry date
                if expiry_date != 'N/A':
                    try:
                        expiry_dt = datetime.datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                        expiry_date = expiry_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        expiry_date = expiry_date[:16]
                
                output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                    idx, 
                    cn[:30], 
                    api_name[:25], 
                    "{} days".format(days_expired),
                    expiry_date[:20]
                ))
            output.append("")
        
        # Critical Certificates Table - TAMPILKAN SEMUA
        critical_certs = results['by_status'].get('CRITICAL', [])
        if critical_certs:
            output.append("🟠 CRITICAL CERTIFICATES (Expiring in ≤ {} days)".format(self.critical_days))
            output.append("-" * 100)
            
            output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                "No", "CN Certificate", "API Name", "Days Left", "Expiry Date"))
            output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                "-"*5, "-"*30, "-"*25, "-"*15, "-"*20))
            
            critical_certs_sorted = sorted(critical_certs, key=lambda x: x.get('days_remaining', 9999))
            
            for idx, cert in enumerate(critical_certs_sorted, 1):
                cn = cert.get('cn', 'Unknown')
                api_name = cert.get('api_name', 'Unknown API')[:25]
                days_left = cert.get('days_remaining', 0)
                expiry_date = cert.get('not_valid_after', 'N/A')
                
                # Format expiry date
                if expiry_date != 'N/A':
                    try:
                        expiry_dt = datetime.datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                        expiry_date = expiry_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        expiry_date = expiry_date[:16]
                
                output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                    idx, 
                    cn[:30], 
                    api_name[:25], 
                    "{} days".format(days_left),
                    expiry_date[:20]
                ))
            output.append("")
        
        # Warning Certificates Table - TAMPILKAN SEMUA (tanpa batasan)
        warning_certs = results['by_status'].get('WARNING', [])
        if warning_certs:
            output.append("🟡 WARNING CERTIFICATES (Expiring in ≤ {} days)".format(self.warning_days))
            output.append("-" * 100)
            
            output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                "No", "CN Certificate", "API Name", "Days Left", "Expiry Date"))
            output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                "-"*5, "-"*30, "-"*25, "-"*15, "-"*20))
            
            warning_certs_sorted = sorted(warning_certs, key=lambda x: x.get('days_remaining', 9999))
            
            # Tampilkan SEMUA warning certificates
            for idx, cert in enumerate(warning_certs_sorted, 1):
                cn = cert.get('cn', 'Unknown')
                api_name = cert.get('api_name', 'Unknown API')[:25]
                days_left = cert.get('days_remaining', 0)
                expiry_date = cert.get('not_valid_after', 'N/A')
                
                # Format expiry date
                if expiry_date != 'N/A':
                    try:
                        expiry_dt = datetime.datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                        expiry_date = expiry_dt.strftime("%Y-%m-%d %H:%M")
                    except:
                        expiry_date = expiry_date[:16]
                
                output.append("{:<5} {:<30} {:<25} {:<15} {:<20}".format(
                    idx, 
                    cn[:30], 
                    api_name[:25], 
                    "{} days".format(days_left),
                    expiry_date[:20]
                ))
            output.append("")
        
        # Footer
        output.append("=" * 100)
        output.append("Generated by Axway Certificate Monitor v3.1")
        output.append("=" * 100)
        
        return '\n'.join(output)
    
    def generate_detailed_report(self, results):
        """Generate detailed human-readable report"""
        report = []
        report.append("=" * 80)
        report.append("AXWAY CA CERTIFICATE MONITORING REPORT")
        report.append("=" * 80)
        report.append("Timestamp: {}".format(results['timestamp']))
        report.append("Axway Host: {}".format(results['axway_host']))
        report.append("Total APIs: {}".format(results['total_proxies']))
        report.append("Total CA Certificates: {}".format(results['total_certificates']))
        report.append("")
        
        # Summary
        report.append("SUMMARY:")
        report.append("-" * 40)
        summary = results['summary']
        report.append("Expired:        {}".format(summary['expired']))
        report.append("Critical (<{}d): {}".format(self.critical_days, summary['critical']))
        report.append("Warning (<{}d): {}".format(self.warning_days, summary['warning']))
        report.append("Valid:          {}".format(summary['valid']))
        report.append("")
        
        return '\n'.join(report)


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
        
        # Generate and display table output jika diminta
        if args.table:
            table_output = monitor.generate_table_output(results)
            print("\n" + table_output)
        
        # Generate detailed report
        detailed_report = monitor.generate_detailed_report(results)
        if args.verbose or args.debug:
            logger.info("\n" + detailed_report)
        
        # Save to files jika diminta
        if args.output_file:
            with open(args.output_file, 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            logger.info("Results saved to {}".format(args.output_file))
        
        if args.report_file:
            with open(args.report_file, 'w', encoding='utf-8') as f:
                f.write(detailed_report)
            logger.info("Detailed report saved to {}".format(args.report_file))
        
        if args.table_file and args.table:
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
