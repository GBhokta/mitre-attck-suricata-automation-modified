import requests
import sqlite3
import logging
from datetime import datetime

# Logging settings
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MitreAttackDatabaseCreator:
    def __init__(self, db_path='mitre_attack.db'):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.api_base_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.create_tables()
        logger.info("MITRE ATT&CK The database creation system has been initialized.")

    def create_tables(self):
        # techniques Create table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS techniques (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            detection TEXT,
            last_updated TEXT
        )
        ''')
        self.conn.commit()
        logger.info("The database table has been created or already exists..")

    def fetch_techniques(self):
        # MITRE ATT&CK Get the data.다.
        logger.info("MITRE ATT&CK Retrieving technical information from...")
        response = requests.get(self.api_base_url)
        if response.status_code == 200:
            data = response.json()
            techniques = [obj for obj in data['objects'] if obj['type'] == 'attack-pattern']
            logger.info(f"Successfully retrieved {len(techniques)} technical information.")
            return techniques
        else:
            logger.error(f"Failed to get technical information: status code {response.status_code}")
            raise Exception(f"Failed to fetch techniques: {response.status_code}")

    def process_techniques(self, techniques):
        # Store technical information in database
        logger.info(f"{len(techniques)}Processing technical information...")
        for technique in techniques:
            technique_id = technique['external_references'][0]['external_id']
            name = technique['name']
            description = technique.get('description', '')
            detection = technique.get('x_mitre_detection', '')
            last_updated = datetime.now().isoformat()

            # techniques Insert data into table
            self.cursor.execute('''
            INSERT OR REPLACE INTO techniques (id, name, description, detection, last_updated)
            VALUES (?, ?, ?, ?, ?)
            ''', (technique_id, name, description, detection, last_updated))
        
        self.conn.commit()
        logger.info("All technical information has been processed and stored in a database.")

    def create_database(self):
        # Manage data collection and processing process
        logger.info("Start the data collection and database creation process")
        techniques = self.fetch_techniques()
        self.process_techniques(techniques)
        logger.info(f"Database creation complete. {len(techniques)} technical information has been stored in the database..")

    def close(self):
        # Close database connection
        self.conn.close()
        logger.info("The database connection has been terminated.")

if __name__ == "__main__":
    # Initialize MITER ATT&CK database generator
    db_creator = MitreAttackDatabaseCreator(db_path='mitre_attack.db')
    db_creator.create_database()
    db_creator.close()
