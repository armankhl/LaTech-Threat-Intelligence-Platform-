import argparse
from nvd_engine import NVDEngine
from db_manager import DatabaseManager
from asset_mapper import AssetMapper

def fetch_and_store_nvd():
    print("=== STEP 1: FETCH NVD DATA ===")
    nvd = NVDEngine()
    daily_threats = nvd.get_daily_high_severity_cves(min_cvss_score=8.0)
    if daily_threats:
        db = DatabaseManager()
        db.save_cves(daily_threats)
        db.close()
    else:
        print("[-] No high severity CVEs to save.")

def map_internal_assets():
    print("=== STEP 2: CORRELATE ASSETS ===")
    mapper = AssetMapper()
    mapper.run_correlation()
    mapper.db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Project Nexus Microservice CLI")
    parser.add_argument("--action", choices=["fetch_nvd", "match_assets"], required=True, help="Action to perform")
    
    args = parser.parse_args()

    if args.action == "fetch_nvd":
        fetch_and_store_nvd()
    elif args.action == "match_assets":
        map_internal_assets()