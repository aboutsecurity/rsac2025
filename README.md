# firmnightware

- clone the repository, set up the KEV database and run the streamlit app 
  ```bash
  git clone git@github.com:markusneis/firmnightware.git
  cd firmwarenightware
  python3 -m venv .venv
  pip install -r requirements.txt
  python3 download_kev.py # first download known exploit vulnerabilities, quit after the download there should be a cisa_vulnerabilities.db
  streamlit run firmnightware.py 
  ```
- Extract your image `binwalk -eM <image>` 
- Run cve-bin-tool using json2 output `cve-bin-tool -f json2 -o report <folder>`

- **OR**
   
- Add a new firmware file to the `firmwares` folder (limited to 25mb file size atm)
- A workflow will kick-off a workflow that will use The https://github.com/intel/cve-bin-tool to analyze firmware and create a cve_report.zip under the `Workflow Run` in the `Actions` Tab
- Extract the `cve_report.zip` and import the `cve-bin-tool-report.json` file into the streamlit app
  





## Streamlit APP - firmnightware.py

### Prerequisites

- Configure Retool Workflow
- set up the vector store and enable it in the workflow
- configure the workflow webhook URL and API KEY in the streamlit app

This script creates a Streamlit web application for visualizing and analyzing vulnerability reports. It provides the following functionalities:

1. **Upload and Parse JSON Reports**: Allows users to upload JSON files containing vulnerability reports from cve-bin-tool 
2. **Display Metadata**: Extracts and displays metadata from the uploaded report, including tool information and generation date.
3. **Database Information**: Shows information about the database, such as the last update date and total entries.
4. **Vulnerabilities Summary**: Summarizes the vulnerabilities by severity and displays them in a table.
5. **CVE Lookup in CISA Database**: Looks up CVE numbers from the report in a local SQLite database and displays the results.
6. **Trigger Retool Workflow**: Allows users to submit CVE numbers to a Retool workflow for further analysis.
7. **Detailed Vulnerabilities Report**: Provides detailed information about vulnerabilities from different data sources within the report.

## Usage

```bash
streamlit run firmnightware.py

```
   

## download_kev.py

This script is designed to download and manage the CISA Known Exploited Vulnerabilities (KEV) feed. It performs the following tasks:

1. **Download the KEV Feed**: Fetches the JSON feed from the CISA website.
2. **Create a SQLite Database**: Sets up a SQLite database to store the vulnerabilities data.
3. **Populate the Database**: Inserts the vulnerabilities data into the database.
4. **Lookup CVE Entries**: Provides an interactive prompt to lookup specific CVE entries in the database.


## Usage

Run the script to download the KEV feed, populate the database, and interactively lookup CVE entries.

```bash
python download_kev.py
```

The database will be saved as `cisa_vulnerabilities.db`.
