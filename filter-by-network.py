import json

# Set file path
file_path = "enterprise-attack.json"

# Load JSON data
with open(file_path, 'r') as f:
    attack_data = json.load(f)

# ATT&CK technology filtering
techniques = [obj for obj in attack_data['objects'] if obj['type'] == 'attack-pattern']

# Network-related keywords
network_keywords = ["network", "traffic", "packet", "connection", "flow", "port", "protocol"]
network_techniques = []

# Filter network-related technologies
for technique in techniques:
    description = technique.get('description', '').lower()
    detection = technique.get('x_mitre_detection', '').lower()
    
    if any(keyword in description or keyword in detection for keyword in network_keywords):
        network_techniques.append(technique)

# Output results
total_techniques = len(techniques)
network_techniques_count = len(network_techniques)

print(f"Total number of ATT&CK techniques: {total_techniques}")
print(f"Number of techniques suitable for network-based detection: {network_techniques_count}")
print(f"Ratio: {network_techniques_count / total_techniques * 100:.2f}%")
# Output some examples of network-related technologies
for tech in network_techniques[:5]:  # Print only the first 5
    print(f"ID: {tech['external_references'][0]['external_id']}, Name: {tech['name']}")
