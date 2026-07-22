import os
import json
import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv
from pathlib import Path


# Load variables from config/.env
env_path = Path(__file__).resolve().parent.parent / "config" / ".env"
load_dotenv(dotenv_path=env_path)

class DatabaseManager:
    def __init__(self):
        # Connect to the PostgreSQL database
        self.conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD")
        )
        self.conn.autocommit = True
        self.cursor = self.conn.cursor()
        self.setup_tables()

    def setup_tables(self):
        """Creates the necessary tables if they do not exist."""
        print("[*] Verifying database schema...")
        
        create_cve_table = """
        CREATE TABLE IF NOT EXISTS daily_cves (
            cve_id VARCHAR(50) PRIMARY KEY,
            base_score FLOAT,
            severity VARCHAR(20),
            description TEXT,
            cwes JSONB,
            cpes JSONB,
            references_links JSONB,
            is_matched BOOLEAN DEFAULT FALSE,
            affected_assets JSONB,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # NEW: Enterprise Asset Inventory Table
        create_asset_table = """
        CREATE TABLE IF NOT EXISTS assets_inventory (
            asset_id VARCHAR(50) PRIMARY KEY,
            hostname VARCHAR(100),
            ip_address VARCHAR(50),  -- Added for Tenable integration
            vendor VARCHAR(100),
            product VARCHAR(100),
            version VARCHAR(50),
            cpe_string VARCHAR(255),
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        self.cursor.execute(create_cve_table)
        self.cursor.execute(create_asset_table)
        print("[+] Database schema is ready.")

    def save_cves(self, cve_list: list):
        """
        Inserts a list of CVE dictionaries into the database.
        Uses ON CONFLICT to avoid inserting duplicate CVEs.
        
        Policy Maintained: ON CONFLICT only updates base_score, severity, 
        and references_links. Fields like description, cwes, cpes, 
        affected_assets, and is_matched are preserved and NOT overwritten.
        """
        if not cve_list:
            print("[-] No CVEs to save.")
            return

        print(f"[*] Saving {len(cve_list)} CVEs to PostgreSQL...")
        
        insert_query = """
            INSERT INTO daily_cves 
            (cve_id, base_score, severity, description, cwes, cpes, references_links, affected_assets, is_matched)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) 
            DO UPDATE SET 
                base_score = EXCLUDED.base_score,
                severity = EXCLUDED.severity,
                references_links = EXCLUDED.references_links;
        """
        
        saved_count = 0
        for cve in cve_list:
            try:
                self.cursor.execute(insert_query, (
                    cve.get("CVE_ID"),
                    cve.get("Base_Score"),
                    cve.get("Severity"),
                    cve.get("Description"),
                    Json(cve.get("CWE", [])),       
                    Json(cve.get("CPEs", [])),      
                    Json(cve.get("References", [])),
                    Json(cve.get("Affected_Assets", [])), # Added: Casts list to JSONB
                    cve.get("Is_Matched", False)          # Added: Defaults to False
                ))
                saved_count += 1
            except Exception as e:
                print(f"[!] Error saving {cve.get('CVE_ID')}: {e}")

        print(f"[+] Successfully saved/updated {saved_count} CVEs in the database.")

    def close(self):
        """Closes the database connection."""
        self.cursor.close()
        self.conn.close()

# ==========================================
# TEST THE DATABASE CONNECTION
# ==========================================
if __name__ == "__main__":
    db = DatabaseManager()
    db.close()
    print("Database connection and setup successful!")