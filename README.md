Phishing Report App
===================

Overview
--------
This app imports Proofpoint CSV data and reported email Excel data, stores it in Postgres, and provides dashboards and reports via Streamlit.

Local Setup (Docker)
-------------------
1) Start services:
   `docker compose up -d --build`
2) Open the app:
   `http://localhost:8501`

Database Migration (schema-only)
--------------------------------
Run the schema migration to ensure tables exist:
`docker exec -i phishing-report-app-db-1 psql -U phishing -d phishing -c "SELECT 1;"`

Or run the app once; it auto-creates tables on startup.

Backup (schema-only, no data)
-----------------------------
This creates a schema-only dump (no rows) and stores it in `backups/`:
`docker exec -i phishing-report-app-db-1 pg_dump -U phishing -d phishing --schema-only > backups/phishing_schema.sql`

Restore schema-only on a new server:
`cat backups/phishing_schema.sql | docker exec -i phishing-report-app-db-1 psql -U phishing -d phishing`

AWS Linux Server Deployment (no data migration)
----------------------------------------------
Assumes an EC2 instance with Docker installed.

1) Install Docker + Compose:
   `sudo yum update -y`
   `sudo yum install -y docker`
   `sudo service docker start`
   `sudo usermod -aG docker ec2-user`
   Log out/in, then:
   `docker version`
   `docker compose version`

2) Copy the project to the server:
   - git clone the repo, or
   - scp/rsync the project folder

3) Build and run:
   `docker compose up -d --build`

4) (Optional) Schema-only restore:
   Use the schema-only backup if you want empty tables pre-created.

App Usage (basic)
-----------------
1) Import Data:
   - Proofpoint CSV: single or bulk import using filenames like `Jan 2025.csv`
   - Reported Excel: use the reported import section (monthly totals)
2) Dashboard:
   View totals, monthly breakdowns, and recent batches.
3) Reports:
   Monthly report for clicked users.
4) Quarterly Report:
   Clicks use Proofpoint data; Reported totals use reported Excel data.
5) False Positives:
   Use Rules or Actions in the unified False Positives menu.

Notes
-----
- Bulk import infers month/year from filenames.
- Reported Excel data uses the selected month for all rows (ignores Created date).
