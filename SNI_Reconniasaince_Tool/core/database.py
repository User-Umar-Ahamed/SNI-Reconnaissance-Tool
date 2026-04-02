import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class ScanResult:
    """Data class for scan results"""
    domain: str
    port: int
    latency: Optional[float]
    status: str  # "Permitted" or "Restricted"


class Database:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = "data/scans.db"):
        """Initialize database connection"""
        self.db_path = db_path
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database schema
        self._init_schema()
    
    def _init_schema(self):
        """Create database tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                scan_type TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        
        # Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                port INTEGER NOT NULL,
                latency REAL,
                status TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_scan(self, name: str, scan_type: str, results: List[ScanResult]) -> int:
        """
        Save a scan and its results to database
        
        Args:
            name: Unique name for the scan
            scan_type: Type of scan ("dns_cache" or "common_sites")
            results: List of ScanResult objects
        
        Returns:
            scan_id of the saved scan
        
        Raises:
            ValueError: If scan name already exists
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insert scan record
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO scans (name, scan_type, timestamp) VALUES (?, ?, ?)",
                (name, scan_type, timestamp)
            )
            scan_id = cursor.lastrowid
            
            # Insert results
            for result in results:
                cursor.execute(
                    """
                    INSERT INTO results (scan_id, domain, port, latency, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scan_id, result.domain, result.port, result.latency, result.status)
                )
            
            conn.commit()
            return scan_id
            
        except sqlite3.IntegrityError:
            raise ValueError(f"A scan named '{name}' already exists. Please choose a different name.")
        finally:
            conn.close()
    
    def get_all_scans(self) -> List[Dict]:
        """
        Retrieve all saved scans
        
        Returns:
            List of scan dictionaries with id, name, scan_type, and timestamp
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, scan_type, timestamp
            FROM scans
            ORDER BY timestamp DESC
        """)
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'name': row[1],
                'scan_type': row[2],
                'timestamp': row[3]
            })
        
        conn.close()
        return scans
    
    def load_scan_results(self, scan_id: int) -> Optional[List[ScanResult]]:
        """
        Load results for a specific scan
        
        Args:
            scan_id: ID of the scan to load
        
        Returns:
            List of ScanResult objects or None if scan not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT domain, port, latency, status
            FROM results
            WHERE scan_id = ?
            ORDER BY domain
        """, (scan_id,))
        
        results = []
        for row in cursor.fetchall():
            results.append(ScanResult(
                domain=row[0],
                port=row[1],
                latency=row[2],
                status=row[3]
            ))
        
        conn.close()
        return results if results else None
    
    def delete_scan(self, scan_id: int):
        """
        Delete a scan and all its results
        
        Args:
            scan_id: ID of the scan to delete
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Delete scan (results are cascade deleted)
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        
        conn.commit()
        conn.close()
    
    def get_scan_info(self, scan_id: int) -> Optional[Dict]:
        """
        Get information about a specific scan
        
        Args:
            scan_id: ID of the scan
        
        Returns:
            Dictionary with scan info or None if not found
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, name, scan_type, timestamp
            FROM scans
            WHERE id = ?
        """, (scan_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'name': row[1],
                'scan_type': row[2],
                'timestamp': row[3]
            }
        return None
