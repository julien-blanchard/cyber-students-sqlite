import sqlite3

# I ran this one only once, to create the database and tables (SALTS, NONCES)
def createDatabase(path_to_database,table_name,col2):
    conn = sqlite3.connect(path_to_database)
    cursor = conn.cursor()
    new_table = f"""
        CREATE TABLE {table_name} (
            Email VARCHAR(255) NOT NULL,
            {col2} VARCHAR(255) NOT NULL
        )
    """
    cursor.execute(new_table)
    conn.commit()
    conn.close()

# we're adding a new row into the table for each new user and their salt / nonce, based on their email
def updateTable(path_to_database,table_name,col1,col2):
    conn = sqlite3.connect(path_to_database)
    cursor = conn.cursor()
    insert_salt = f"""
        INSERT INTO {table_name} VALUES ('{col1}', '{col2}') -- col1: email, col2: salt or nonce
    """
    cursor.execute(insert_salt)
    conn.commit()
    conn.close()

# we'll use this for authentifying / logging in, to retrieve the salt / nonce from the email address
def retrieveFromTable(path_to_database,table_name,col1):
    conn = sqlite3.connect(path_to_database)
    cursor = conn.cursor()
    query = f"""
        SELECT * from {table_name} WHERE Email = '{col1}'
    """
    cursor.execute(query)
    result = cursor.fetchall()[0][1] # SQLite's returns lists for each row within a main tuple
    conn.close()
    return result