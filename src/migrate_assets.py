import pandas as pd
from db_manager import DatabaseManager
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path="config/.env")

def migrate_csv_to_db():
    db = DatabaseManager()
    csv_path = Path(__file__).resolve().parent.parent / "data" / "assets.csv"
    
    print(f"[*] Reading assets from {csv_path}...")
    try:
        df = pd.read_csv(csv_path).fillna("")
    except Exception as e:
        print(f"[!] Failed to read CSV: {e}")
        return

    inserted = 0
    for _, row in df.iterrows():
        # Assign a placeholder IP if it doesn't exist in CSV
        ip_address = row.get("IP_Address", "0.0.0.0") 
        
        query = """
            INSERT INTO assets_inventory (asset_id, hostname, ip_address, vendor, product, version, cpe_string)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (asset_id) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                ip_address = EXCLUDED.ip_address,
                version = EXCLUDED.version;
        """
        try:
            db.cursor.execute(query, (
                row["Asset_ID"], row["Hostname"], ip_address, 
                row["Vendor"], row["Product"], row["Version"], row["CPE_String"]
            ))
            inserted += 1
        except Exception as e:
            print(f"[!] Failed to insert {row['Asset_ID']}: {e}")

    print(f"[+] Successfully migrated {inserted} assets to PostgreSQL!")
    db.close()

if __name__ == "__main__":
    migrate_csv_to_db()