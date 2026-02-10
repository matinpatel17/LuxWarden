## Database Setup

1. Create a MySQL database named `luxwarden`.
2. Import the schema using the provided SQL file:
   - Open MySQL Workbench.
   - Go to **Server** -> **Data Import**.
   - Select "Import from Self-Contained File" and choose `database_schema.sql`.
   - Click **Start Import**.
3. Update your `.env` file with your local database credentials.