import sqlite3
from abstract.abstractprovider import AbstractProvider
from provenancedata import ProvenanceData


class SqliteProvider(AbstractProvider):
    """Provider template class"""

    def __init__(self):
        super().__init__()
        self.db = 'prov.db'
        self.init_db()
        return

    def init_db(self):
        conn = sqlite3.connect(self.db)

        # init data base schema
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS provenancedata
                  (ProvenanceHash text NOT NULL PRIMARY KEY UNIQUE,
                   ChoreographyInstanceId text NOT NULL,
                   WorkflowInstanceID text NOT NULL,
                   WorkflowVersion text NOT NULL,
                   Input text NOT NULL,
                   Output text NOT NULL,
                   InvokeSignature blob NOT NULL,
                   ExecuteSignature blob NOT NULL,
                   timestamp blob NOT NULL,
                   predecessor text NOT NULL)''')

        conn.commit()
        conn.close()

    def record(self, pd: ProvenanceData) -> bool:
        conn = sqlite3.connect(self.db)

        c = conn.cursor()
        try:
            c.execute("""INSERT INTO provenancedata ('ProvenanceHash' ,
                      'ChoreographyInstanceId', 'WorkflowInstanceID',
                      'WorkflowVersion', 'Input', 'Output',
                      'InvokeSignature', 'ExecuteSignature', 'timestamp', 'predecessor')
                      VALUES (?,?,?,?,?,?,?,?,?,?)""", pd.values())
            return_code = True
        except sqlite3.IntegrityError:
            print("Provenance entry is already in database.")
            return_code = False
        conn.commit()
        conn.close()
        return return_code

    def retrieve(self):
        pass

    def migrate(self):
        pass

    def flush(self):
        """Delete provenancedata from Database"""
        conn = sqlite3.connect(self.db)
        c = conn.cursor()

        try:
            c.execute("""DELETE FROM provenancedata""")
            return_code = True
        except sqlite3.Error as e:
            print(e)
            return_code = False
        conn.commit()
        conn.close()
        return return_code

