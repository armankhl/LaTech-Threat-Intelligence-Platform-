import pandas as pd
import json
from db_manager import DatabaseManager
from pathlib import Path

class AssetMapper:
    def __init__(self):
        self.db = DatabaseManager()
        self.csv_path = Path(__file__).resolve().parent.parent / "data" / "assets.csv"

    def load_assets(self):
        """Loads the organization's assets from the CSV file."""
        print(f"[*] Loading assets from {self.csv_path}...")
        try:
            # fillna("") ensures empty cells don't break string operations
            return pd.read_csv(self.csv_path).fillna("")
        except Exception as e:
            print(f"[!] Error loading CSV: {e}")
            return pd.DataFrame()

    def run_correlation(self):
        """Matches database CVEs against the CSV inventory."""
        assets_df = self.load_assets()
        if assets_df.empty:
            return

        # Widen the interval to 30 days to completely ignore timezone/NVD lag issues
        self.db.cursor.execute("""
            SELECT cve_id, cpes 
            FROM daily_cves 
            WHERE discovered_at >= NOW() - INTERVAL '30 days'
        """)
        cves = self.db.cursor.fetchall()
        print(f"[*] Analyzing {len(cves)} recent CVEs against internal assets...")

        matched_cves = 0

        for cve_id, cve_cpes in cves:
            # Failsafe: Ensure psycopg2 parsed the JSONB correctly
            if isinstance(cve_cpes, str):
                try:
                    cve_cpes = json.loads(cve_cpes)
                except json.JSONDecodeError:
                    continue
                    
            if not cve_cpes or not isinstance(cve_cpes, list):
                continue

            affected_internal_assets = []

            for vul_cpe in cve_cpes:
                for _, asset in assets_df.iterrows():
                    # Extract Vendor and Product safely
                    vendor = str(asset['Vendor']).strip().lower()
                    product = str(asset['Product']).strip().lower()
                    
                    # We wrap them in colons so "windows" doesn't accidentally match "windows_server"
                    # NVD CPE format: cpe:2.3:o:microsoft:windows_server:2019...
                    match_string = f":{vendor}:{product}:"
                    
                    if match_string in vul_cpe.lower():
                        affected_internal_assets.append({
                            "Asset_ID": asset["Asset_ID"],
                            "Hostname": asset["Hostname"],
                            "Product": f"{asset['Vendor']} {asset['Product']}"
                        })

            if affected_internal_assets:
                # Remove duplicates in case multiple CPEs matched the same asset
                unique_assets = list({a['Asset_ID']: a for a in affected_internal_assets}.values())
                
                # Better logging to see exactly what matched!
                print(f"[+] MATCH FOUND: {cve_id} affects {len(unique_assets)} asset(s)! (e.g., {unique_assets[0]['Hostname']})")
                
                update_query = """
                    UPDATE daily_cves 
                    SET is_matched = TRUE, affected_assets = %s
                    WHERE cve_id = %s
                """
                self.db.cursor.execute(update_query, (json.dumps(unique_assets), cve_id))
                matched_cves += 1

        print(f"[*] Correlation complete. {matched_cves} relevant CVEs found for the organization.")

# ==========================================
# TEST THE MAPPER
# ==========================================
if __name__ == "__main__":
    mapper = AssetMapper()
    mapper.run_correlation()
    mapper.db.close()