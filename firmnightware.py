import streamlit as st
import json
import pandas as pd
import requests
import sqlite3

DB_PATH = "cisa_vulnerabilities.db"  # SQLite database file

def lookup_cves_in_db(cve_list):
    """Lookup a list of CVE numbers in the SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        placeholders = ",".join("?" for _ in cve_list)
        query = f"SELECT * FROM vulnerabilities WHERE cveID IN ({placeholders})"
        df = pd.read_sql_query(query, conn, params=cve_list)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame()

def main():
    st.title("Vulnerability Report Dashboard")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        retool_url = st.text_input(
            "Retool Workflow URL", 
            value="https://api.retool.com/v1/workflows/aaa24e53-5e2c-4eed-a08e-506e7485a5f3/startTrigger",
            type="default"
        )
        api_key = st.text_input(
            "Retool API Key", 
            value="retool_wk_0473f1dbc0f24729bd12555ef2a516d3", 
            type="password"
        )
    
    st.markdown("Upload a JSON file to display the dashboard.")

    # File uploader (accepts only .json files)
    uploaded_file = st.file_uploader("Upload Vulnerability JSON File", type=["json"])
    
    if uploaded_file is not None:
        try:
            file_bytes = uploaded_file.read()
            file_text = file_bytes.decode("utf-8")
        except Exception as e:
            st.error(f"Error reading file: {e}")
            return
        
        try:
            report_data = json.loads(file_text)
        except Exception as e:
            st.error(f"Error parsing JSON: {e}")
            return

        # ---------------------------
        # Metadata Section
        # ---------------------------
        metadata = report_data.get("metadata", {})
        tool_info = metadata.get("tool", {})
        generation_date = metadata.get("generation_date", "Unknown")
        tool_name = tool_info.get("name", "Unknown")
        tool_version = tool_info.get("version", "Unknown")
        
        header_md = f"""
# Vulnerability Report Dashboard

**Tool:** {tool_name} v{tool_version}  
**Generated on:** {generation_date}
        """
        st.markdown(header_md)

        # ---------------------------
        # Database Information Section (from the JSON file)
        # ---------------------------
        db_info = report_data.get("database_info", {})
        last_updated = db_info.get("last_updated", "N/A")
        total_entries = db_info.get("total_entries", {})
        db_info_md = f"""
**Database Last Updated:** {last_updated}  

**Total Entries:**
        """
        for key, value in total_entries.items():
            db_info_md += f"- **{key}**: {value}  \n"
        st.markdown(db_info_md)

        # ---------------------------
        # Vulnerabilities Summary Section
        # ---------------------------
        vulnerabilities = report_data.get("vulnerabilities", {})
        summary = vulnerabilities.get("summary", {})
        st.markdown("## Vulnerabilities Summary")
        if summary:
            summary_df = pd.DataFrame(list(summary.items()), columns=["Severity", "Count"])
            total_vulns = summary_df["Count"].sum()
            summary_df.loc[len(summary_df)] = ["Total", total_vulns]
            st.table(summary_df)
        else:
            st.markdown("No summary available.")

        # ---------------------------
        # Extract All CVE Numbers from Report Sections
        # ---------------------------
        all_cve_numbers = []
        report_sections = vulnerabilities.get("report", [])
        if report_sections:
            for section in report_sections:
                entries = section.get("entries", [])
                for entry in entries:
                    cve = entry.get("cve_number")
                    if cve:
                        all_cve_numbers.append(cve)
        all_cve_numbers = sorted(set(all_cve_numbers))

        # ---------------------------
        # CVE Lookup in CISA Database Section
        # ---------------------------
        st.markdown("## CVE Lookup in CISA Database")
        if all_cve_numbers:
            filter_text = st.text_input("Filter CVE numbers or descriptions for DB lookup", key="db_filter",
                                        help="Enter any string to filter CVEs by ID or description (year, keyword, etc.)")
            if filter_text:
                # First, filter by CVE ID
                id_filtered = [cve for cve in all_cve_numbers if filter_text.lower() in cve.lower()]
                
                # Then, try to find CVEs with matching descriptions in the database
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    # Use LIKE with wildcards for partial matching in description
                    query = f"SELECT cveID FROM vulnerabilities WHERE shortDescription LIKE ? OR vulnerabilityName LIKE ?"
                    search_pattern = f"%{filter_text}%"
                    cursor.execute(query, (search_pattern, search_pattern))
                    desc_matches = [row[0] for row in cursor.fetchall() if row[0] in all_cve_numbers]
                    conn.close()
                    
                    # Combine both filter results without duplicates
                    filtered_cves = sorted(set(id_filtered + desc_matches))
                except Exception as e:
                    st.error(f"Error searching database: {e}")
                    filtered_cves = id_filtered
            else:
                filtered_cves = all_cve_numbers

            if filtered_cves:
                found_df = lookup_cves_in_db(filtered_cves)
                if not found_df.empty:
                    st.markdown("### CVEs Found in CISA Database")
                    st.table(found_df)
                else:
                    st.info("No matching CVEs found in the CISA database.")
            else:
                st.warning("No CVE numbers match your filter.")
        else:
            st.info("No CVE numbers found in the report.")

        # ---------------------------
        # Trigger Retool Workflow Analysis Section (above detailed report)
        # ---------------------------
        st.markdown("## Trigger Retool Workflow Analysis")
        if all_cve_numbers:
            filter_text2 = st.text_input("Filter CVE numbers or descriptions for Retool", key="retool_filter", 
                                         help="Enter any string to filter CVEs by ID or description (year, keyword, etc.)")
            
            if filter_text2:
                # First, filter by CVE ID
                id_filtered = [cve for cve in all_cve_numbers if filter_text2.lower() in cve.lower()]
                
                # Then, try to find CVEs with matching descriptions in the database
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    # Use LIKE with wildcards for partial matching in description
                    query = f"SELECT cveID FROM vulnerabilities WHERE shortDescription LIKE ? OR vulnerabilityName LIKE ?"
                    search_pattern = f"%{filter_text2}%"
                    cursor.execute(query, (search_pattern, search_pattern))
                    desc_matches = [row[0] for row in cursor.fetchall() if row[0] in all_cve_numbers]
                    conn.close()
                    
                    # Combine both filter results without duplicates
                    retool_filtered = sorted(set(id_filtered + desc_matches))
                except Exception as e:
                    st.error(f"Error searching database: {e}")
                    retool_filtered = id_filtered
            else:
                retool_filtered = all_cve_numbers
            
            if not retool_filtered:
                st.warning("No CVE numbers match your filter for Retool.")
            else:
                selected_cve = st.selectbox("Choose a CVE to submit to Retool", options=retool_filtered)
                if st.button("Submit to Retool Workflow"):
                    payload = {"cve": selected_cve}
                    headers = {
                        "Content-Type": "application/json",
                        "X-Workflow-Api-Key": api_key,
                    }
                    try:
                        response = requests.post(retool_url, json=payload, headers=headers)
                        if response.status_code == 200:
                            # Replace literal "\n" sequences with actual newlines
                            formatted_response = response.text.replace("\\n", "\n")
                            with st.expander("Attack Tree Analysis"):
                                st.markdown(formatted_response)
                        else:
                            st.error(f"Error: Received status code {response.status_code}")
                            st.text(response.text)
                    except Exception as e:
                        st.error(f"Request failed: {e}")
        else:
            st.info("No CVE numbers found in the report.")

        # ---------------------------
        # Detailed Vulnerabilities Report Section
        # ---------------------------
        st.markdown("## Detailed Vulnerabilities Report")
        if report_sections:
            for section in report_sections:
                datasource = section.get("datasource", "Unknown Source")
                entries = section.get("entries", [])
                st.markdown(f"### Vulnerabilities from **{datasource}**")
                if entries:
                    df_entries = pd.DataFrame(entries)
                    table_filter = st.text_input(f"Filter table for {datasource}", key=datasource)
                    if table_filter:
                        df_entries = df_entries[df_entries.apply(
                            lambda row: row.astype(str).str.contains(table_filter, case=False).any(), axis=1)]
                    st.table(df_entries)
                else:
                    st.markdown("No entries found for this datasource.")
        else:
            st.markdown("No detailed report available.")
    else:
        st.info("Please upload a JSON file to view the vulnerability dashboard.")

if __name__ == "__main__":
    main()
