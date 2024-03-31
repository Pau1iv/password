import sqlite3
import secrets
from hashlib import pbkdf2_hmac

class PasswordManager:
    """
    A simple password manager that securely stores passwords using PBKDF2-HMAC algorithm.
    """

    def __init__(self, db_name='passwords.db'):
        """
        Initializes the PasswordManager instance with a SQLite database connection.

        Args:
            db_name (str): Name of the SQLite database file. Defaults to 'passwords.db'.
        """
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        """
        Creates a table in the database to store hashed passwords and their hashes and salts.
        """
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                               (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT, salt TEXT)''')
        self.conn.commit()

    def store_password(self, password):
        """
        Hashes the provided password and stores it in the database with a randomly generated salt.

        Args:
            password (str): The password to be hashed and stored.
        """
        salt = secrets.token_hex(16)
        hashed_password = self.hash_password(password, salt)
        self.cursor.execute("INSERT INTO passwords (hash, salt) VALUES (?, ?)", (hashed_password, salt))
        self.conn.commit()

    def verify_password(self, password):
        """
        Verifies if the provided password matches any of the stored hashed passwords.

        Args:
            password (str): The password to be verified.

        Returns:
            bool: True if the password is verified, False otherwise.
        """
        self.cursor.execute("SELECT hash, salt FROM passwords")
        stored_data = self.cursor.fetchall()
        for stored_hash, salt in stored_data:
            if self.hash_password(password, salt) == stored_hash:
                return True
        return False

    def hash_password(self, password, salt):
        """
        Hashes the provided password using PBKDF2-HMAC algorithm.

        Args:
            password (str): The password to be hashed.
            salt (str): The salt to be used in hashing.

        Returns:
            str: The hashed password.
        """
        iterations = 100000
        key = pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
        return key.hex()
