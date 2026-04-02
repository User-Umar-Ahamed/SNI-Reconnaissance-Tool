import csv
import json
from typing import List
from datetime import datetime
from core.scanners import ScanResult


class ExportManager:
    """Export scan results"""
    
    def export_to_csv(self, results: List[ScanResult], filename: str):
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Domain', 'Status', 'Latency (ms)', 'Use as SNI'])
            
            for result in sorted(results, key=lambda x: x.domain):
                latency = f"{result.latency:.2f}" if result.latency else "N/A"
                use_sni = "Yes" if result.status == "Valid SNI" else "No"
                writer.writerow([result.domain, result.status, latency, use_sni])
    
    def export_to_json(self, results: List[ScanResult], filename: str):
        valid = sum(1 for r in results if r.status == "Valid SNI")
        blocked = sum(1 for r in results if r.status == "Blocked")
        
        data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_domains': len(results),
            'valid_sni': valid,
            'blocked': blocked,
            'results': [
                {
                    'domain': r.domain,
                    'status': r.status,
                    'latency_ms': round(r.latency, 2) if r.latency else None,
                    'use_as_sni': r.status == "Valid SNI"
                }
                for r in sorted(results, key=lambda x: x.domain)
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=2)
    
    def export_to_txt(self, results: List[ScanResult], filename: str):
        with open(filename, 'w', encoding='utf-8') as txtfile:
            txtfile.write("SNI Reconnaissance Tool - Results\n")
            txtfile.write("=" * 60 + "\n")
            txtfile.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            txtfile.write(f"Total: {len(results)}\n\n")
            
            valid = [r for r in results if r.status == "Valid SNI"]
            blocked = [r for r in results if r.status == "Blocked"]
            
            txtfile.write(f"✅ Valid SNI: {len(valid)}\n")
            txtfile.write(f"🚫 Blocked: {len(blocked)}\n")
            txtfile.write("=" * 60 + "\n\n")
            
            if valid:
                txtfile.write("✅ VALID SNIs (Use these!):\n")
                txtfile.write("-" * 60 + "\n")
                for r in sorted(valid, key=lambda x: x.latency or 9999):
                    latency = f"{r.latency:.0f}ms" if r.latency else "N/A"
                    txtfile.write(f"{r.domain:<40} {latency:>10}\n")
                txtfile.write("\n")
            
            if blocked:
                txtfile.write("🚫 BLOCKED (Don't use):\n")
                txtfile.write("-" * 60 + "\n")
                for r in sorted(blocked, key=lambda x: x.domain):
                    txtfile.write(f"{r.domain}\n")
