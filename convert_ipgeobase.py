import sqlite3
import os
from ipaddress import ip_address

def convert_to_sqlite():
    cities_path = os.path.join('ipgeobase', 'cities.txt')
    cidr_path = os.path.join('ipgeobase', 'cidr_optim.txt')
    conn = sqlite3.connect('ipgeo.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS cities')
    cursor.execute('DROP TABLE IF EXISTS ip_ranges')

    cursor.execute('''
    CREATE TABLE cities (
        city_id TEXT PRIMARY KEY,
        city TEXT,
        region TEXT,
        lat REAL,
        lon REAL
    )''')

    cursor.execute('''
    CREATE TABLE ip_ranges (
        ip_start INTEGER,
        ip_end INTEGER,
        city_id TEXT,
        FOREIGN KEY (city_id) REFERENCES cities(city_id)
    )''')

    with open(cities_path, 'r', encoding='windows-1251') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                cursor.execute(
                    'INSERT INTO cities VALUES (?, ?, ?, ?, ?)',
                    (parts[0], parts[1], parts[2], float(parts[4]), float(parts[5]))
                ) 

    with open(cidr_path, 'r', encoding='windows-1251') as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) >= 3:
                cursor.execute(
                    'INSERT INTO ip_ranges VALUES (?, ?, ?)',
                    (int(parts[0]), int(parts[1]), parts[2])
                )
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    convert_to_sqlite()