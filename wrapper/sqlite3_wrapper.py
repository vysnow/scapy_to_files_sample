#!/usr/bin/env python
# coding: shift-jis
import sqlite3

class SqlWapper:
    """
    This is sample code.
    This class create new sqlite3 file
    This class can't do anything else..
    """

    def __init__(self, db):
        """Initialize
        """
        self.db = db
        self.conn = sqlite3.connect(db)

    def init_table(self, table):
        """Init a table
        """
        cursor = self.conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS " + table + " (TIMESTAMP TEXT, Host TEXT, Dest TEXT, Protocal Text, Summary Text, Data BLOB);")
        self.conn.commit()

    def add_row(self, row):
        """ Add row
        """
        #Creating a cursor object using the cursor() method
        cursor = self.conn.cursor()
        query = '''
            INSERT INTO Packet(
                TIMESTAMP, Host, Dest, Protocal, Summary, Data
            ) VALUES 
            (?, ?, ?, ?, ?, ?);
        '''
        cursor.execute(query, row)

        # Commit your changes in the database
        self.conn.commit()

    def save(self):
        """Save db file.

        Parameters
        ----------
        name : str
            File name
        """
        # Closing the connection
        self.conn.close()
        return
