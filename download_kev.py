import sqlite3
import requests
import json

# URL of the CISA Known Exploited Vulnerabilities feed
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def download_feed(url):
    response = requests.get(url)
    response.raise_for_status()  # raises an exception if the download fails
    return response.json()

def create_database(db_path="cisa_vulnerabilities.db"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Create the vulnerabilities table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cveID TEXT PRIMARY KEY,
            vendorProject TEXT,
            product TEXT,
            vulnerabilityName TEXT,
            dateAdded TEXT,
            shortDescription TEXT,
            requiredAction TEXT,
            dueDate TEXT,
            knownRansomwareCampaignUse TEXT,
            notes TEXT,
            cwes TEXT
        )
    """)
    conn.commit()
    return conn

def populate_database(conn, vulnerabilities):
    c = conn.cursor()
    for vuln in vulnerabilities:
        cveID = vuln.get("cveID")
        vendorProject = vuln.get("vendorProject")
        product = vuln.get("product")
        vulnerabilityName = vuln.get("vulnerabilityName")
        dateAdded = vuln.get("dateAdded")
        shortDescription = vuln.get("shortDescription")
        requiredAction = vuln.get("requiredAction")
        dueDate = vuln.get("dueDate")
        knownRansomwareCampaignUse = vuln.get("knownRansomwareCampaignUse")
        notes = vuln.get("notes")
        # Store CWEs as a comma-separated string
        cwes = ", ".join(vuln.get("cwes", []))
        try:
            c.execute("""
                INSERT OR REPLACE INTO vulnerabilities (
                    cveID, vendorProject, product, vulnerabilityName, dateAdded,
                    shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse,
                    notes, cwes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cveID, vendorProject, product, vulnerabilityName, dateAdded,
                  shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse,
                  notes, cwes))
        except sqlite3.Error as e:
            print(f"SQLite error for {cveID}: {e}")
    conn.commit()

def lookup_cve(conn, cve_number):
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE cveID = ?", (cve_number,))
    row = c.fetchone()
    if row:
        # Fetch column names to display results in a dict format
        columns = [desc[0] for desc in c.description]
        return dict(zip(columns, row))
    return None

def main():
    # Download the JSON feed from CISA
    print("Downloading vulnerability feed...")
    data = download_feed(FEED_URL)
    
    # The feed has a top-level field "vulnerabilities" that is a list
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        print("No vulnerabilities found in the feed.")
        return

    # Create and populate the SQLite database
    conn = create_database()
    print("Populating database...")
    populate_database(conn, vulnerabilities)
    print("Database populated and saved as 'cisa_vulnerabilities.db'.")

    # Interactive lookup loop
    while True:
        cve_input = input("Enter a CVE number to lookup (or type 'quit' to exit): ").strip()
        if cve_input.lower() in ["quit", "exit"]:
            break
        result = lookup_cve(conn, cve_input)
        if result:
            print("\nVulnerability found:")
            for key, value in result.items():
                print(f"{key}: {value}")
            print("\n" + "-"*50)
        else:
            print(f"No entry found for {cve_input}\n")
    
    conn.close()
    print("Exiting.")

if __name__ == "__main__":
    main()
