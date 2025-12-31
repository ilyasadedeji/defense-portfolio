"""
Highway Checkpoint Verification System - Day 3, Session 2
Defense Application: Automated security checks at military/police checkpoints
Mission: Catch criminals, stolen vehicles, and threats at checkpoints
"""

import sqlite3
import json
from datetime import datetime
import random
import string

# 🔵 TYPE THIS - Database initialization (NEW CONCEPT: SQL databases)
def initialize_database():
    """
    Create and populate database with sample data
    In production, this would connect to national databases
    """
    conn = sqlite3.connect('checkpoint_database.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vehicles (
            plate_number TEXT PRIMARY KEY,
            owner_name TEXT,
            owner_phone TEXT,
            vehicle_make TEXT,
            vehicle_model TEXT,
            vehicle_color TEXT,
            registration_date TEXT,
            state_registered TEXT,
            status TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS wanted_persons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            aliases TEXT,
            date_of_birth TEXT,
            gender TEXT,
            state_of_origin TEXT,
            crime TEXT,
            wanted_level TEXT,
            last_seen_location TEXT,
            reward_amount INTEGER,
            bvn TEXT,
            nin TEXT,
            phone_numbers TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stolen_vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plate_number TEXT,
            vehicle_make TEXT,
            vehicle_model TEXT,
            vehicle_color TEXT,
            stolen_date TEXT,
            stolen_location TEXT,
            owner_name TEXT,
            owner_phone TEXT,
            case_number TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checkpoint_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checkpoint_name TEXT,
            timestamp TEXT,
            plate_number TEXT,
            driver_name TEXT,
            passengers INTEGER,
            verification_result TEXT,
            action_taken TEXT,
            officer_name TEXT,
            notes TEXT
        )
    ''')
    
    conn.commit()
    
    # Check if data already exists
    cursor.execute('SELECT COUNT(*) FROM vehicles')
    if cursor.fetchone()[0] == 0:
        populate_sample_data(conn, cursor)
    
    conn.close()
    print("✓ Database initialized successfully")


# 🟢 COPY-PASTE OK - Sample data population
def populate_sample_data(conn, cursor):
    """Populate database with sample Nigerian data"""
    
    # Sample vehicles (mix of legitimate and stolen)
    sample_vehicles = [
        ('ABC-123-XY', 'Adewale Johnson', '08012345678', 'Toyota', 'Corolla', 'Silver', '2023-01-15', 'Lagos', 'Active'),
        ('KAD-456-ZZ', 'Amina Bello', '08098765432', 'Honda', 'Accord', 'Black', '2022-06-20', 'Kaduna', 'Active'),
        ('ABJ-789-FG', 'Chidi Okafor', '07012345678', 'Mercedes', 'C-Class', 'White', '2024-03-10', 'FCT', 'Active'),
        ('KAN-234-AB', 'Fatima Yusuf', '09087654321', 'Lexus', 'RX350', 'Blue', '2023-11-05', 'Kano', 'Active'),
        ('LAG-567-CD', 'Emeka Nwosu', '08123456789', 'Toyota', 'Camry', 'Gray', '2022-08-18', 'Lagos', 'Active'),
        ('ZAM-890-EF', 'Ibrahim Musa', '07098765432', 'Nissan', 'Pathfinder', 'Red', '2021-04-22', 'Zamfara', 'Suspended'),
        ('BOR-345-GH', 'Blessing Eze', '09012345678', 'Ford', 'Explorer', 'Green', '2023-09-30', 'Borno', 'Active'),
        ('OYO-678-IJ', 'Tunde Adeyemi', '08087654321', 'Hyundai', 'Elantra', 'Silver', '2024-01-12', 'Oyo', 'Active'),
    ]
    
    cursor.executemany('''
        INSERT INTO vehicles VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_vehicles)
    
    # Sample wanted persons (terrorists, kidnappers, bandits)
    sample_wanted = [
        ('Musa Abubakar', 'Abu Shekau, The Commander', '1985-03-15', 'Male', 'Borno', 
         'Terrorism, Mass Murder', 'HIGH', 'Sambisa Forest', 50000000, '12345678901', '11122233344', '08011122233'),
        ('Sani Garba', 'Dogo Gide', '1990-07-22', 'Male', 'Zamfara', 
         'Banditry, Kidnapping, Armed Robbery', 'HIGH', 'Zamfara forests', 20000000, '23456789012', '22233344455', '07022334455'),
        ('Ibrahim Mohammed', 'Yellow', '1988-11-30', 'Male', 'Kaduna', 
         'Kidnapping, Murder', 'MEDIUM', 'Kaduna-Abuja highway', 10000000, '34567890123', '33344455566', '09033445566'),
        ('Usman Suleiman', 'Dankarami', '1992-02-18', 'Male', 'Katsina', 
         'Cattle Rustling, Armed Robbery', 'MEDIUM', 'Katsina-Zamfara border', 5000000, '45678901234', '44455566677', '08144556677'),
        ('Hassan Lawal', 'Turji', '1987-09-05', 'Male', 'Niger', 
         'Banditry, Kidnapping', 'HIGH', 'Niger State', 15000000, '56789012345', '55566677788', '07055667788'),
    ]
    
    cursor.executemany('''
        INSERT INTO wanted_persons (full_name, aliases, date_of_birth, gender, state_of_origin,
                                   crime, wanted_level, last_seen_location, reward_amount, bvn, nin, phone_numbers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_wanted)
    
    # Sample stolen vehicles
    sample_stolen = [
        ('KAD-999-XX', 'Toyota', 'Hilux', 'White', '2024-11-15', 'Kaduna-Abuja Road', 
         'John Okeke', '08099887766', 'CASE-2024-1156'),
        ('ABJ-888-YY', 'Honda', 'Pilot', 'Black', '2024-10-20', 'Abuja City Center', 
         'Sarah Ibrahim', '07088776655', 'CASE-2024-1089'),
        ('LAG-777-ZZ', 'Lexus', 'LX570', 'Silver', '2024-09-05', 'Lagos-Ibadan Expressway', 
         'Chief Adebayo', '08177665544', 'CASE-2024-0923'),
    ]
    
    cursor.executemany('''
        INSERT INTO stolen_vehicles (plate_number, vehicle_make, vehicle_model, vehicle_color,
                                    stolen_date, stolen_location, owner_name, owner_phone, case_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', sample_stolen)
    
    conn.commit()
    print("✓ Sample data populated")


# 🔵 TYPE THIS - Vehicle verification (CORE LOGIC)
def verify_vehicle(plate_number):
    """
    Verify vehicle registration and check if stolen
    Returns verification result with recommendations
    """
    conn = sqlite3.connect('checkpoint_database.db')
    cursor = conn.cursor()
    
    # Check if vehicle is registered
    cursor.execute('SELECT * FROM vehicles WHERE plate_number = ?', (plate_number,))
    vehicle = cursor.fetchone()
    
    # Check if vehicle is stolen
    cursor.execute('SELECT * FROM stolen_vehicles WHERE plate_number = ?', (plate_number,))
    stolen = cursor.fetchone()
    
    conn.close()
    
    result = {
        'plate_number': plate_number,
        'is_registered': vehicle is not None,
        'is_stolen': stolen is not None,
        'alert_level': 'CLEAR',
        'action': 'ALLOW_PASSAGE',
        'details': {}
    }
    
    if stolen:
        result['alert_level'] = 'CRITICAL'
        result['action'] = 'DETAIN_IMMEDIATELY'
        result['details'] = {
            'status': '🚨 STOLEN VEHICLE',
            'make_model': f"{stolen[2]} {stolen[3]}",
            'color': stolen[4],
            'stolen_date': stolen[5],
            'stolen_location': stolen[6],
            'owner': stolen[7],
            'owner_phone': stolen[8],
            'case_number': stolen[9]
        }
    elif not vehicle:
        result['alert_level'] = 'HIGH'
        result['action'] = 'DETAILED_INSPECTION'
        result['details'] = {
            'status': '⚠️ UNREGISTERED VEHICLE',
            'issue': 'No registration found in database',
            'recommendation': 'Verify physical documents, possible fake plates'
        }
    elif vehicle[8] == 'Suspended':
        result['alert_level'] = 'MEDIUM'
        result['action'] = 'VERIFY_DOCUMENTS'
        result['details'] = {
            'status': '⚠️ SUSPENDED REGISTRATION',
            'owner': vehicle[1],
            'phone': vehicle[2],
            'vehicle': f"{vehicle[3]} {vehicle[4]} ({vehicle[5]})",
            'registered': vehicle[7],
            'issue': 'Registration suspended - verify reason'
        }
    else:
        result['alert_level'] = 'CLEAR'
        result['action'] = 'ALLOW_PASSAGE'
        result['details'] = {
            'status': '✓ VERIFIED',
            'owner': vehicle[1],
            'phone': vehicle[2],
            'vehicle': f"{vehicle[3]} {vehicle[4]} ({vehicle[5]})",
            'registered': vehicle[7]
        }
    
    return result


# 🔵 TYPE THIS - Person verification (CRITICAL SECURITY)
def search_wanted_person(name=None, phone=None, bvn=None, nin=None):
    """
    Search for wanted persons by name, phone, BVN, or NIN
    Returns match results with threat level
    """
    conn = sqlite3.connect('checkpoint_database.db')
    cursor = conn.cursor()
    
    matches = []
    
    if name:
        cursor.execute('''
            SELECT * FROM wanted_persons 
            WHERE full_name LIKE ? OR aliases LIKE ?
        ''', (f'%{name}%', f'%{name}%'))
        matches.extend(cursor.fetchall())
    
    if phone:
        cursor.execute('''
            SELECT * FROM wanted_persons 
            WHERE phone_numbers LIKE ?
        ''', (f'%{phone}%',))
        matches.extend(cursor.fetchall())
    
    if bvn:
        cursor.execute('''
            SELECT * FROM wanted_persons 
            WHERE bvn = ?
        ''', (bvn,))
        matches.extend(cursor.fetchall())
    
    if nin:
        cursor.execute('''
            SELECT * FROM wanted_persons 
            WHERE nin = ?
        ''', (nin,))
        matches.extend(cursor.fetchall())
    
    conn.close()
    
    # Remove duplicates
    unique_matches = []
    seen_ids = set()
    for match in matches:
        if match[0] not in seen_ids:
            unique_matches.append(match)
            seen_ids.add(match[0])
    
    if unique_matches:
        return {
            'found': True,
            'alert_level': 'CRITICAL',
            'action': 'ARREST_IMMEDIATELY',
            'matches': [{
                'name': m[1],
                'aliases': m[2],
                'dob': m[3],
                'gender': m[4],
                'state': m[5],
                'crime': m[6],
                'wanted_level': m[7],
                'last_seen': m[8],
                'reward': f"₦{m[9]:,}",
                'bvn': m[10],
                'nin': m[11],
                'phone': m[12]
            } for m in unique_matches]
        }
    else:
        return {
            'found': False,
            'alert_level': 'CLEAR',
            'action': 'ALLOW_PASSAGE',
            'message': 'No matches in wanted persons database'
        }


# 🔵 TYPE THIS - Log checkpoint activity
def log_checkpoint_activity(checkpoint_name, plate_number, driver_name, 
                            passengers, verification_result, action_taken, 
                            officer_name, notes=""):
    """
    Log all checkpoint activities for audit trail
    Critical for accountability and pattern analysis
    """
    conn = sqlite3.connect('checkpoint_database.db')
    cursor = conn.cursor()
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute('''
        INSERT INTO checkpoint_logs 
        (checkpoint_name, timestamp, plate_number, driver_name, passengers,
         verification_result, action_taken, officer_name, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (checkpoint_name, timestamp, plate_number, driver_name, passengers,
          verification_result, action_taken, officer_name, notes))
    
    conn.commit()
    conn.close()
    
    return timestamp


# 🟢 COPY-PASTE OK - Display functions
def display_vehicle_verification(result):
    """Display vehicle verification results"""
    print("\n" + "=" * 80)
    print("🚗 VEHICLE VERIFICATION RESULT")
    print("=" * 80)
    print()
    
    print(f"Plate Number: {result['plate_number']}")
    print(f"Alert Level: {result['alert_level']}")
    print(f"Recommended Action: {result['action']}")
    print()
    
    print("Details:")
    print("-" * 80)
    for key, value in result['details'].items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    
    print()
    print("=" * 80)


def display_person_search(result):
    """Display person search results"""
    print("\n" + "=" * 80)
    print("👤 WANTED PERSON SEARCH RESULT")
    print("=" * 80)
    print()
    
    if result['found']:
        print(f"🚨 ALERT: {len(result['matches'])} MATCH(ES) FOUND!")
        print(f"Alert Level: {result['alert_level']}")
        print(f"Action Required: {result['action']}")
        print()
        
        for i, match in enumerate(result['matches'], 1):
            print(f"Match {i}:")
            print("-" * 80)
            print(f"  Name: {match['name']}")
            print(f"  Aliases: {match['aliases']}")
            print(f"  DOB: {match['dob']}")
            print(f"  State of Origin: {match['state']}")
            print(f"  Crimes: {match['crime']}")
            print(f"  Wanted Level: {match['wanted_level']}")
            print(f"  Last Seen: {match['last_seen']}")
            print(f"  Reward: {match['reward']}")
            print(f"  BVN: {match['bvn']}")
            print(f"  NIN: {match['nin']}")
            print(f"  Phone: {match['phone']}")
            print()
    else:
        print("✓ No matches found in wanted persons database")
        print(f"Alert Level: {result['alert_level']}")
        print(f"Action: {result['action']}")
    
    print("=" * 80)


# 🔵 TYPE THIS - Main checkpoint interface
def checkpoint_interface():
    """
    Main checkpoint verification interface
    Used by security personnel at checkpoints
    """
    print("\n" + "=" * 80)
    print("🛡️  NIGERIAN MILITARY/POLICE CHECKPOINT SYSTEM")
    print("Automated Security Verification Platform")
    print("=" * 80)
    print()
    
    # Get checkpoint details
    checkpoints = [
        "Kaduna-Abuja Highway (KM 45)",
        "Abuja-Lokoja Road (KM 32)",
        "Lagos-Ibadan Expressway (KM 67)",
        "Kano-Kaduna Road (KM 78)",
        "Port Harcourt-Aba Road (KM 23)"
    ]
    
    print("Select Checkpoint:")
    for i, cp in enumerate(checkpoints, 1):
        print(f"  {i}. {cp}")
    
    checkpoint_choice = input("\nEnter checkpoint number: ").strip()
    checkpoint_map = {str(i): cp for i, cp in enumerate(checkpoints, 1)}
    checkpoint_name = checkpoint_map.get(checkpoint_choice, checkpoints[0])
    
    officer_name = input("Enter officer name: ").strip()
    
    print(f"\n✓ Checkpoint: {checkpoint_name}")
    print(f"✓ Officer: {officer_name}")
    print(f"✓ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    while True:
        print("\n" + "=" * 80)
        print("CHECKPOINT OPERATIONS")
        print("=" * 80)
        print()
        print("1. Verify Vehicle")
        print("2. Search Wanted Person")
        print("3. View Checkpoint Logs")
        print("4. Exit/Change Checkpoint")
        
        choice = input("\nSelect operation: ").strip()
        
        if choice == '1':
            # Vehicle verification
            plate = input("\nEnter vehicle plate number: ").strip().upper()
            driver = input("Enter driver name: ").strip()
            passengers = input("Number of passengers: ").strip()
            
            print("\nVerifying vehicle...")
            result = verify_vehicle(plate)
            display_vehicle_verification(result)
            
            # Log activity
            log_checkpoint_activity(
                checkpoint_name, plate, driver, passengers,
                result['alert_level'], result['action'], officer_name,
                json.dumps(result['details'])
            )
            
            print(f"\n✓ Activity logged")
            
        elif choice == '2':
            # Person search
            print("\nSearch wanted persons by:")
            print("1. Name")
            print("2. Phone Number")
            print("3. BVN")
            print("4. NIN")
            
            search_choice = input("\nSelect search method: ").strip()
            
            name = phone = bvn = nin = None
            
            if search_choice == '1':
                name = input("Enter name: ").strip()
            elif search_choice == '2':
                phone = input("Enter phone number: ").strip()
            elif search_choice == '3':
                bvn = input("Enter BVN: ").strip()
            elif search_choice == '4':
                nin = input("Enter NIN: ").strip()
            
            print("\nSearching database...")
            result = search_wanted_person(name, phone, bvn, nin)
            display_person_search(result)
            
        elif choice == '3':
            # View logs
            view_checkpoint_logs(checkpoint_name)
            
        elif choice == '4':
            print("\n✓ Checkpoint session ended")
            break
        else:
            print("\n⚠️ Invalid choice")


def view_checkpoint_logs(checkpoint_name=None, limit=10):
    """View recent checkpoint activities"""
    conn = sqlite3.connect('checkpoint_database.db')
    cursor = conn.cursor()
    
    if checkpoint_name:
        cursor.execute('''
            SELECT * FROM checkpoint_logs 
            WHERE checkpoint_name = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (checkpoint_name, limit))
    else:
        cursor.execute('''
            SELECT * FROM checkpoint_logs 
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (limit,))
    
    logs = cursor.fetchall()
    conn.close()
    
    print("\n" + "=" * 80)
    print("📋 CHECKPOINT ACTIVITY LOGS")
    print("=" * 80)
    print()
    
    if logs:
        for log in logs:
            print(f"Time: {log[2]}")
            print(f"Checkpoint: {log[1]}")
            print(f"Vehicle: {log[3]} | Driver: {log[4]} | Passengers: {log[5]}")
            print(f"Result: {log[6]} | Action: {log[7]}")
            print(f"Officer: {log[8]}")
            print("-" * 80)
    else:
        print("No logs found")
    
    print("=" * 80)


def main():
    """Main program"""
    print("\n🇳🇬 INITIALIZING CHECKPOINT SYSTEM...")
    initialize_database()
    print()
    
    while True:
        print("\n" + "=" * 80)
        print("NIGERIAN CHECKPOINT VERIFICATION SYSTEM")
        print("=" * 80)
        print()
        print("1. Start Checkpoint Operations")
        print("2. View All Checkpoint Logs")
        print("3. Test Vehicle Verification")
        print("4. Test Person Search")
        print("5. Exit System")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == '1':
            checkpoint_interface()
        elif choice == '2':
            view_checkpoint_logs(limit=20)
        elif choice == '3':
            # Quick test
            test_plates = ['ABC-123-XY', 'KAD-999-XX', 'FAKE-111-ZZ']
            for plate in test_plates:
                result = verify_vehicle(plate)
                display_vehicle_verification(result)
                input("\nPress Enter for next test...")
        elif choice == '4':
            # Quick test
            result = search_wanted_person(name="Musa")
            display_person_search(result)
        elif choice == '5':
            print("\n✓ System shutdown")
            break
        else:
            print("\n⚠️ Invalid choice")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ System interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")