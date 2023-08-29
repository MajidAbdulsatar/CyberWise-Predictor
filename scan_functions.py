import re
import csv
import subprocess
from tqdm import tqdm
import os

def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, shell=True, text=True)
    return result.stdout

def list_docker_images(namespace):
    command = f'docker images --format "{{{{.Repository}}}}:{{{{.Tag}}}}" {namespace}/*'
    result = run_command(command)
    return result.strip().split('\n')

def run_trivy_scan(image):
    command = f'trivy image {image} 2>/dev/null'
    return run_command(command)

def scan(namespace):
    # Create directory if not exists
    os.makedirs('./data/scan_results', exist_ok=True)

    csv_file_path = f"./data/scan_results/{namespace}.csv"
    log_file_path = './data/scan_results/scan_log.txt'

    docker_images = list_docker_images(namespace)
    total_images = len(docker_images)

    if total_images == 0:
        print(f"Error: Namespace {namespace} not found.")
        return

    with open(log_file_path, 'a') as log_file:
        log_file.write(f"Started scanning namespace: {namespace}\n")

    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        
        # Write the header
        writer.writerow(['Namespace', 'Image', 'CVE'])
        
        # Wrap the iteration with tqdm to create a progress bar
        for image in tqdm(docker_images, total=total_images, desc="Scanning Images"):
            trivy_output = run_trivy_scan(image)
            
            # Use regex to find all CVE numbers
            cve_numbers = re.findall(r'CVE-\d{4}-\d+', trivy_output)
            
            # Write the results to the CSV file
            for cve_number in cve_numbers:
                row = [namespace, image, cve_number]
                writer.writerow(row)

        print(f"Results saved to {csv_file_path}")

    with open(log_file_path, 'a') as log_file:
        log_file.write(f"Completed scanning namespace: {namespace}\n")
