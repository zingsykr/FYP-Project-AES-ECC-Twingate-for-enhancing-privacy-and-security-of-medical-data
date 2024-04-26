import os
import random
from datetime import datetime, timedelta
import schedule
import pandas as pd

dataset_path = '/home/kali/bp_log.csv'
dataset = pd.read_csv(dataset_path)
dataset2_path = '/home/kali/Dataset for People for their Blood Glucose Level with their Superficial body feature readings..xlsx'
dataset2 = pd.read_excel(dataset2_path)


def generate_blood_pressure_values(patient_id):
    current_time = datetime.now()
    random_row = dataset.sample(n=1)

# Generate the output file name based on the patient ID
    output_file = f"blood_pressure_data_{patient_id}.txt"

    with open(output_file, 'a') as file:   
        timestamp =  current_time - timedelta(hours=random.randint(0, 24))       
        systolic_pressure = int(random_row['SYS'])
        diastolic_pressure = int(random_row['DIA'])
        pulse = int(random_row['Pulse'])
        file.write(f"Timestamp: {timestamp} | Systolic Pressure: {systolic_pressure} | Diastolic Pressure: {diastolic_pressure} | Pulse: {pulse}\n")      

        blood_pressure_values = [systolic_pressure, diastolic_pressure, pulse]
        #hashed_blood_pressure = self.hash_blood_pressure(blood_pressure_values)
        print(f"Patient {patient_id} | Timestamp: {timestamp} | Systolic Pressure: {systolic_pressure} | Diastolic Pressure: {diastolic_pressure} | Pulse: {pulse}")

        if systolic_pressure > 120 or diastolic_pressure > 80:
            print(f"Patient {patient_id} | Emergency Alert! Abnormal Blood Pressure Values!")

    return systolic_pressure, diastolic_pressure, pulse

def generate_daily_bp_data(num_records, patient_id):
    # Initialize a list to store the collected data
    collected_data = []
    current_time = datetime.now()

    # Simulate collecting data every 5 hours for 24 hours
    for hour in range(num_records):
        # Generate a fake timestamp within a range of the past 24 hours
        fake_timestamp = current_time - timedelta(hours=random.randint(0, 24))          

        # Generate blood pressure data
        systolic, diastolic, pulse = generate_blood_pressure_values(patient_id)
        
        # Append the data to the list
        collected_data.append((fake_timestamp, systolic, diastolic, pulse))
   # return collected_data


def collect_and_save_data(patient_id):
    data = generate_daily_bp_data(5, patient_id)

    # Save the data to a file
   # save_data_to_file(data, patient_id)


def save_data_to_file(data, filename):
    filename = f"{user_id}_blood_pressure_data.txt"
    with open(filename, 'w') as file:
        for record in data:
            # Convert the timestamp to a string
            timestamp_str = record[0].strftime("%Y-%m-%d %H:%M:%S")
            # Write each record to the file
            file.write(f"{timestamp_str},{record[1]},{record[2]},{record[3]}\n")

