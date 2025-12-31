"""
Nigerian Crime Pattern Analyzer - Day 3, Session 1
Defense Application: Predictive policing and threat intelligence
Mission: Identify kidnapping hotspots and predict future attacks
"""

import pandas as pd
import json
from datetime import datetime, timedelta
from collections import Counter
import matplotlib.pyplot as plt

#  Core analysis function (NEW CONCEPT: data aggregation)
def analyze_crime_patterns(incidents):
    """
    Analyze crime incidents to identify patterns
    Returns hotspots, temporal patterns, and risk scores
    """
    analysis = {
        'total_incidents': len(incidents),
        'hotspot_states': {},
        'hotspot_lgas': {},
        'time_patterns': {},
        'day_patterns': {},
        'crime_types': {},
        'trends': {}
    }
    
    # Analyze by state
    for incident in incidents:
        state = incident.get('state', 'Unknown')
        analysis['hotspot_states'][state] = analysis['hotspot_states'].get(state, 0) + 1
    
    # Analyze by LGA (Local Government Area)
    for incident in incidents:
        lga = incident.get('lga', 'Unknown')
        analysis['hotspot_lgas'][lga] = analysis['hotspot_lgas'].get(lga, 0) + 1
    
    # 🔵 TYPE THIS - Temporal analysis (NEW PATTERN)
    for incident in incidents:
        # Time of day analysis
        hour = incident.get('hour', 'Unknown')
        if hour != 'Unknown':
            time_category = categorize_time(hour)
            analysis['time_patterns'][time_category] = \
                analysis['time_patterns'].get(time_category, 0) + 1
        
        # Day of week analysis
        day = incident.get('day_of_week', 'Unknown')
        analysis['day_patterns'][day] = analysis['day_patterns'].get(day, 0) + 1
        
        # Crime type analysis
        crime_type = incident.get('type', 'Unknown')
        analysis['crime_types'][crime_type] = analysis['crime_types'].get(crime_type, 0) + 1
    
    return analysis


# 🟢 - Helper function
def categorize_time(hour):
    """Categorize hour into time periods"""
    if 6 <= hour < 12:
        return "Morning (6AM-12PM)"
    elif 12 <= hour < 18:
        return "Afternoon (12PM-6PM)"
    elif 18 <= hour < 24:
        return "Evening (6PM-12AM)"
    else:
        return "Night (12AM-6AM)"


# 🔵 - Risk scoring algorithm (IMPORTANT LOGIC)
def calculate_risk_score(state, lga, time_category, analysis):
    """
    Calculate risk score for a specific location and time
    Score: 0-100 (100 = highest risk)
    """
    score = 0
    
    # State risk (40% weight)
    total_incidents = analysis['total_incidents']
    state_incidents = analysis['hotspot_states'].get(state, 0)
    state_risk = (state_incidents / total_incidents) * 100 if total_incidents > 0 else 0
    score += state_risk * 0.4
    
    # LGA risk (30% weight)
    lga_incidents = analysis['hotspot_lgas'].get(lga, 0)
    lga_risk = (lga_incidents / total_incidents) * 100 if total_incidents > 0 else 0
    score += lga_risk * 0.3
    
    # Time risk (30% weight)
    time_incidents = analysis['time_patterns'].get(time_category, 0)
    time_risk = (time_incidents / total_incidents) * 100 if total_incidents > 0 else 0
    score += time_risk * 0.3
    
    return round(score, 2)


# 🟢 - Display functions
def display_analysis(analysis):
    """Display analysis results in formatted output"""
    print("=" * 80)
    print("NIGERIAN CRIME PATTERN ANALYSIS REPORT")
    print("National Security Intelligence")
    print("=" * 80)
    print()
    
    print(f"📊 OVERVIEW")
    print("-" * 80)
    print(f"Total Incidents Analyzed: {analysis['total_incidents']}")
    print()
    
    # Top 5 hotspot states
    print("🔴 TOP 5 HOTSPOT STATES")
    print("-" * 80)
    sorted_states = sorted(analysis['hotspot_states'].items(), 
                          key=lambda x: x[1], reverse=True)[:5]
    for i, (state, count) in enumerate(sorted_states, 1):
        percentage = (count / analysis['total_incidents']) * 100
        print(f"  {i}. {state:20} - {count:3} incidents ({percentage:.1f}%)")
    print()
    
    # Top 5 hotspot LGAs
    print("🔴 TOP 5 HOTSPOT LGAs")
    print("-" * 80)
    sorted_lgas = sorted(analysis['hotspot_lgas'].items(), 
                        key=lambda x: x[1], reverse=True)[:5]
    for i, (lga, count) in enumerate(sorted_lgas, 1):
        percentage = (count / analysis['total_incidents']) * 100
        print(f"  {i}. {lga:30} - {count:3} incidents ({percentage:.1f}%)")
    print()
    
    # Time patterns
    print("⏰ TIME PATTERN ANALYSIS")
    print("-" * 80)
    for time_period, count in sorted(analysis['time_patterns'].items(), 
                                    key=lambda x: x[1], reverse=True):
        percentage = (count / analysis['total_incidents']) * 100
        print(f"  {time_period:25} - {count:3} incidents ({percentage:.1f}%)")
    print()
    
    # Day patterns
    print("📅 DAY OF WEEK ANALYSIS")
    print("-" * 80)
    days_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 
                  'Friday', 'Saturday', 'Sunday']
    for day in days_order:
        count = analysis['day_patterns'].get(day, 0)
        if count > 0:
            percentage = (count / analysis['total_incidents']) * 100
            print(f"  {day:15} - {count:3} incidents ({percentage:.1f}%)")
    print()
    
    # Crime types
    print("🚨 CRIME TYPE BREAKDOWN")
    print("-" * 80)
    for crime_type, count in sorted(analysis['crime_types'].items(), 
                                   key=lambda x: x[1], reverse=True):
        percentage = (count / analysis['total_incidents']) * 100
        print(f"  {crime_type:25} - {count:3} incidents ({percentage:.1f}%)")
    print()
    print("=" * 80)


# 🔵 TYPE THIS - Prediction function (AI LOGIC)
def predict_high_risk_zones(analysis, top_n=10):
    """
    Predict high-risk zones based on analysis
    Returns list of zones with risk scores
    """
    predictions = []
    
    # Get top states and LGAs
    top_states = sorted(analysis['hotspot_states'].items(), 
                       key=lambda x: x[1], reverse=True)[:5]
    top_lgas = sorted(analysis['hotspot_lgas'].items(), 
                     key=lambda x: x[1], reverse=True)[:10]
    
    # Get most dangerous time
    most_dangerous_time = max(analysis['time_patterns'].items(), 
                             key=lambda x: x[1])[0]
    
    # Generate predictions for top LGAs
    for lga, incidents in top_lgas:
        # Find which state this LGA belongs to (simplified)
        state = "Unknown"
        for s in top_states:
            if incidents > 0:
                state = s[0]
                break
        
        risk_score = calculate_risk_score(state, lga, most_dangerous_time, analysis)
        
        predictions.append({
            'location': f"{lga}, {state}",
            'risk_score': risk_score,
            'historical_incidents': incidents,
            'high_risk_time': most_dangerous_time
        })
    
    # Sort by risk score
    predictions.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return predictions[:top_n]


def display_predictions(predictions):
    """Display risk predictions"""
    print("=" * 80)
    print("🎯 HIGH-RISK ZONE PREDICTIONS")
    print("Intelligence for Security Force Deployment")
    print("=" * 80)
    print()
    
    for i, pred in enumerate(predictions, 1):
        risk_level = "CRITICAL" if pred['risk_score'] > 15 else \
                    "HIGH" if pred['risk_score'] > 10 else "ELEVATED"
        
        print(f"{i}. {pred['location']}")
        print(f"   Risk Score: {pred['risk_score']:.2f}/100 - {risk_level} ⚠️")
        print(f"   Historical Incidents: {pred['historical_incidents']}")
        print(f"   High-Risk Period: {pred['high_risk_time']}")
        print(f"   Recommendation: {'Deploy additional forces immediately' if risk_level == 'CRITICAL' else 'Enhanced monitoring required'}")
        print()
    
    print("=" * 80)


# 🟢 COPY-PASTE OK - Sample data generator
def generate_sample_data():
    """
    Generate sample Nigerian crime data
    In production, this would load from real database
    """
    # Nigerian states with security challenges
    high_risk_states = ['Zamfara', 'Kaduna', 'Katsina', 'Niger', 'Plateau']
    medium_risk_states = ['Borno', 'Yobe', 'Adamawa', 'Taraba', 'Benue']
    low_risk_states = ['FCT', 'Kano', 'Sokoto', 'Kebbi', 'Nasarawa']
    
    # Sample LGAs
    lgas = {
        'Zamfara': ['Anka', 'Maru', 'Gusau', 'Tsafe', 'Bungudu'],
        'Kaduna': ['Birnin Gwari', 'Chikun', 'Giwa', 'Igabi', 'Kaduna North'],
        'Katsina': ['Jibia', 'Batsari', 'Safana', 'Dandume', 'Faskari'],
        'Niger': ['Shiroro', 'Munya', 'Rafi', 'Mariga', 'Mashegu'],
        'Plateau': ['Barkin Ladi', 'Riyom', 'Jos South', 'Bassa', 'Mangu']
    }
    
    crime_types = ['Kidnapping', 'Banditry', 'Armed Robbery', 'Cattle Rustling', 
                   'Terrorism', 'Communal Clash']
    
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    incidents = []
    
    # Generate 200 sample incidents
    import random
    random.seed(42)  # For reproducibility
    
    for _ in range(200):
        state = random.choice(high_risk_states + medium_risk_states + low_risk_states)
        
        # High-risk states get more incidents
        if state in high_risk_states:
            if random.random() > 0.3:  # 70% chance
                continue
        
        lga_list = lgas.get(state, ['Unknown LGA'])
        lga = random.choice(lga_list)
        
        incident = {
            'state': state,
            'lga': lga,
            'type': random.choice(crime_types),
            'hour': random.randint(0, 23),
            'day_of_week': random.choice(days),
            'casualties': random.randint(0, 15),
            'date': (datetime.now() - timedelta(days=random.randint(0, 365))).strftime('%Y-%m-%d')
        }
        
        incidents.append(incident)
    
    return incidents


def save_analysis_report(analysis, predictions, filename='crime_analysis_report.json'):
    """Save analysis to file for later use"""
    report = {
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'analysis': analysis,
        'predictions': predictions
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✅ Analysis report saved to {filename}")


# 🔵 Main program (CRITICAL FLOW)
def main():
    """
    Main program - Crime Pattern Analysis System
    """
    print("\n🇳🇬 NIGERIAN SECURITY INTELLIGENCE SYSTEM")
    print("Crime Pattern Analysis & Prediction")
    print("=" * 80)
    print()
    
    print("Loading crime incident data...")
    
    # In production, this would load from database
    # For now, we use sample data
    incidents = generate_sample_data()
    print(f"✓ Loaded {len(incidents)} incident records")
    print()
    
    input("Press Enter to begin analysis...")
    print()
    
    # Perform analysis
    print("Analyzing crime patterns...")
    analysis = analyze_crime_patterns(incidents)
    print("✓ Analysis complete")
    print()
    
    # Display results
    display_analysis(analysis)
    
    input("\nPress Enter to view risk predictions...")
    print()
    
    # Generate predictions
    predictions = predict_high_risk_zones(analysis, top_n=10)
    display_predictions(predictions)
    
    # Save report
    save_choice = input("\nSave analysis report? (y/n): ").strip().lower()
    if save_choice == 'y':
        save_analysis_report(analysis, predictions)
    
    # Interactive risk checker
    print("\n" + "=" * 80)
    print("INTERACTIVE RISK CHECKER")
    print("=" * 80)
    
    while True:
        check_another = input("\nCheck risk for a specific location? (y/n): ").strip().lower()
        if check_another != 'y':
            break
        
        state = input("Enter state name: ").strip().title()
        lga = input("Enter LGA name: ").strip().title()
        
        print("\nSelect time period:")
        print("1. Morning (6AM-12PM)")
        print("2. Afternoon (12PM-6PM)")
        print("3. Evening (6PM-12AM)")
        print("4. Night (12AM-6AM)")
        
        time_choice = input("Enter choice (1-4): ").strip()
        time_map = {
            '1': 'Morning (6AM-12PM)',
            '2': 'Afternoon (12PM-6PM)',
            '3': 'Evening (6PM-12AM)',
            '4': 'Night (12AM-6AM)'
        }
        time_category = time_map.get(time_choice, 'Morning (6AM-12PM)')
        
        # Calculate risk
        risk_score = calculate_risk_score(state, lga, time_category, analysis)
        
        print("\n" + "-" * 80)
        print(f"📍 Location: {lga}, {state}")
        print(f"⏰ Time Period: {time_category}")
        print(f"⚠️  Risk Score: {risk_score:.2f}/100")
        
        if risk_score > 15:
            print(f"🚨 Risk Level: CRITICAL - Avoid travel, deploy security forces")
        elif risk_score > 10:
            print(f"⚠️  Risk Level: HIGH - Travel with armed escort only")
        elif risk_score > 5:
            print(f"⚡ Risk Level: ELEVATED - Exercise extreme caution")
        else:
            print(f"✓ Risk Level: LOW - Standard security protocols")
        print("-" * 80)
    
    print("\n✅ Analysis session complete")
    print("=" * 80)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")