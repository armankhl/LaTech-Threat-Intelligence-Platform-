import os
import time
from tenable.sc import TenableSC
from dotenv import load_dotenv

class TenableEngine:
    def __init__(self):
        load_dotenv(dotenv_path="../config/.env")
        
        self.host = os.getenv("TENABLE_SC_HOST")
        self.access_key = os.getenv("TENABLE_SC_ACCESS_KEY")
        self.secret_key = os.getenv("TENABLE_SC_SECRET_KEY")
        self.repo_id = os.getenv("TENABLE_REPO_ID", "1")
        
        # Connect to Tenable.sc
        try:
            self.sc = TenableSC(self.host, access_key=self.access_key, secret_key=self.secret_key)
            print("[+] Successfully connected to Tenable.sc API.")
        except Exception as e:
            print(f"[!] Failed to connect to Tenable.sc: {e}")
            self.sc = None

    def search_plugin_by_cve(self, cve_id: str) -> list:
        """
        1. Searches Tenable for plugins associated with a specific CVE.
        """
        if not self.sc: return []
        
        print(f"[*] Searching Tenable.sc for plugins matching {cve_id}...")
        plugins = []
        try:
            # Query the Tenable plugin database
            for plugin in self.sc.plugins.list(fields=['id', 'name', 'family', 'riskFactor'], filter=('cve', '=', cve_id)):
                plugins.append(plugin)
            
            print(f"[+] Found {len(plugins)} plugins for {cve_id}.")
            return plugins
        except Exception as e:
            print(f"[!] Error fetching plugins: {e}")
            return []

    def check_asset_vulnerability(self, ip_address: str, cve_id: str = None) -> dict:
        """
        2. Checks if an IP already has known vulnerabilities in the Tenable Repository.
        """
        if not self.sc: return {}
        print(f"[*] Checking existing vulnerability data for {ip_address}...")
        
        try:
            # Search the vulnerability database for this specific IP
            filters = [('ip', '=', ip_address)]
            if cve_id:
                filters.append(('cve', '=', cve_id))
                
            vulns = self.sc.analysis.vulns(*filters, tool='vulndetails')
            
            results = [v for v in vulns]
            if results:
                print(f"[+] Found {len(results)} existing vulnerabilities on {ip_address}.")
                return {"exists": True, "vulnerabilities": results}
            return {"exists": False, "vulnerabilities": []}
            
        except Exception as e:
            print(f"[!] Error checking asset: {e}")
            return {"exists": False, "error": str(e)}

    def launch_targeted_scan(self, ip_address: str, plugin_id: int, scan_name: str) -> dict:
        """
        3 & 4. Launch a targeted Active Scan on an IP for a specific Plugin.
        """
        if not self.sc: return {}
        print(f"[*] Launching targeted scan on {ip_address} for Plugin {plugin_id}...")
        
        try:
            # Create a Scan object in Tenable
            scan = self.sc.scans.create(
                name=f"Nexus_Targeted_{scan_name}",
                repo=int(self.repo_id),
                targets=[ip_address],
                # For an enterprise setup, you would reference a specific Scan Policy ID here.
                # policy_id=1
            )
            
            # Launch the scan
            scan_instance = self.sc.scans.launch(scan['id'])
            print(f"[+] Scan launched successfully. Scan Result ID: {scan_instance['scanResult']['id']}")
            
            return {
                "scan_id": scan['id'],
                "scan_result_id": scan_instance['scanResult']['id'],
                "status": "Launched"
            }
        except Exception as e:
            print(f"[!] Error launching scan: {e}")
            return {"status": "Error", "details": str(e)}

    def get_scan_report(self, scan_result_id: int):
        """
        5 & 6. Wait for the scan to finish and extract the report.
        """
        if not self.sc: return None
        print(f"[*] Checking status of Scan Result {scan_result_id}...")
        
        try:
            # Poll status until it completes
            status = self.sc.scan_instances.status(scan_result_id)
            while status in ['Pending', 'Running']:
                print(f"[*] Scan is {status}. Waiting 30 seconds...")
                time.sleep(30)
                status = self.sc.scan_instances.status(scan_result_id)
                
            if status == 'Completed':
                print("[+] Scan Completed! Extracting Vulnerability Report...")
                # Extract the vulnerabilities found in this specific scan instance
                vulns = self.sc.analysis.vulns(('scanID', '=', scan_result_id), tool='vulndetails')
                report = [v for v in vulns]
                return {"status": "Completed", "findings": report}
            else:
                return {"status": status, "findings": []}
                
        except Exception as e:
            print(f"[!] Error retrieving scan report: {e}")
            return None