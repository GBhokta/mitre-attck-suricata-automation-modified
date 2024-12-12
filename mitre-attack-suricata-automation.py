# MITRE ATT&CK Techniques Automation with Suricata - Kim Jae Myung (2024.8.15.)
# Copyright (c) 2024 Kim Jae Myung. All rights reserved.  (Author: hellcosmos@gmail.com)
# Enterpise Matrix: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

import json
import os
import re
import sqlite3
import subprocess
import tempfile
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import HumanMessage

# Logging settings (set to debug level to print all debug messages)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Class representing Suricata rules
class SuricataRule:
    def __init__(self, header: str, options: Dict[str, str]):
        # Initialize rule headers and options
        self.header = header
        self.options = options

    def __str__(self):
        # Returns the rule as a string in Suricata format
        options_str = " ".join([f"{k}:{v};" if v else f"{k};" for k, v in self.options.items()])
        return f"{self.header} ({options_str})"

# Class to validate Suricata rules
class SuricataRuleValidator:
    def __init__(self, technique_id: str, technique_name: str):
        # Initialize the technology ID and name, and initialize the list to store errors and warnings
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate(self, rule: str) -> Tuple[bool, Dict[str, Any]]:
        # Perform verification for given rules
        self.errors = []
        self.warnings = []
        result = {
            "header": None,
            "options": {}
        }

        # Rule header validation
        header_match = re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip|http|ftp|tls|smb|dns|modbus|enip)\s+.*?\s+.*?\s+.*?$', rule, re.MULTILINE)
        if header_match:
            result["header"] = header_match.group(0)
        else:
            self.errors.append("Invalid rule header")  # Invalid rule header

       # Verify options
        options_match = re.search(r'\((.*)\)$', rule, re.DOTALL)
        if options_match:
            options = options_match.group(1).split(';')
            for option in options:
                option = option.strip()
                if ':' in option:
                    key, value = option.split(':', 1)
                    result["options"][key.strip()] = value.strip()
                else:
                    result["options"][option] = None
        else:
            self.errors.append("Missing rule options")  # If an option is missing

       # Check required options
        required_options = ['msg', 'sid', 'rev', 'classtype', 'reference']
        for option in required_options:
            if option not in result["options"]:
                self.errors.append(f"Missing required option: {option}")  # Required options missing

  # Check for technology-related patterns (check if the technology name is explicitly included in the rule)      
        if not re.search(re.escape(self.technique_name), rule, re.IGNORECASE):
            self.warnings.append(f"No explicit reference to technique '{self.technique_name}' found")

     # Call additional verification logic
        self._check_content_matches(rule)
        self._check_performance_impact(rule)
        self._check_evasion_resistance(rule)

        is_valid = len(self.errors) == 0
        return is_valid, result

    # Check if there is a content or pcre match
    def _check_content_matches(self, rule: str):
        if 'content:' not in rule and 'pcre:' not in rule:
            self.warnings.append("Rule doesn't contain any content or pcre matches")

   # Review the performance impact of the rules
    def _check_performance_impact(self, rule: str):
        if rule.count('content:') > 5 or rule.count('pcre:') > 3:
            self.warnings.append("Rule contains a high number of content or pcre matches, which might impact performance")

  # Check if the rule is evasion resistant 
    def _check_evasion_resistance(self, rule: str):
        if 'nocase;' not in rule and 'pcre:' not in rule:
            self.warnings.append("Rule might be susceptible to simple evasion techniques")

   # Generate verification result report
    def get_report(self) -> str:
        report = f"Validation Report for {self.technique_name} ({self.technique_id})\n"
        report += "=" * 50 + "\n\n"

        if self.errors:
            report += "Errors:\n"
            for error in self.errors:
                report += f"- {error}\n"
            report += "\n"

        if self.warnings:
            report += "Warnings:\n"
            for warning in self.warnings:
                report += f"- {warning}\n"
            report += "\n"

        if not self.errors and not self.warnings:
            report += "No errors or warnings found. The rule appears to be valid.\n"

        return report

# Class that simulates Suricata rules
class SuricataSimulator:
    def __init__(self):
      # Initialize list to store loaded rules
        self.rules: List[SuricataRule] = []

# load rules
    def load_rule(self, rule: SuricataRule):
        self.rules.append(rule)

# Simulate packet traffic to see if the rule is triggered
    def simulate_traffic(self, packet: Dict[str, Any]) -> Tuple[bool, List[str]]:
        alerts = []
        for rule in self.rules:
            if self._rule_matches(rule, packet):
                alerts.append(f"Alert triggered: {rule.options.get('msg', 'Unknown alert')}")  # Add warning message
        
        return len(alerts) > 0, alerts

  # Check if the rule matches the given packet  
    def _rule_matches(self, rule: SuricataRule, packet: Dict[str, Any]) -> bool:
        protocol = rule.header.split()[1]
        if protocol != packet.get('protocol'):
            logger.debug(f"Protocol mismatch: rule expects {protocol}, packet has {packet.get('protocol')}")
            return False

        if 'content' in rule.options and rule.options['content'] not in packet.get('payload', ''):
            logger.debug(f"Content mismatch: rule expects content {rule.options['content']}, packet has {packet.get('payload', '')}")
            return False

        if 'pcre' in rule.options:
            pcre_pattern = rule.options['pcre']
            if not re.search(pcre_pattern, packet.get('payload', '')):
                logger.debug(f"PCRE mismatch: rule expects pcre {pcre_pattern}, packet has {packet.get('payload', '')}")
                return False

        return True

# MITER ATT&CK Suricata system class
class MitreAttackSuricataSystem:
    def __init__(self, openai_api_key, db_path='mitre_attack.db', suricata_path='suricata'):
# Initialize main settings and connect to database       
        self.db_path = db_path
        self.suricata_path = suricata_path
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.chat_model = ChatOpenAI(model="gpt-4o-mini", temperature=0, openai_api_key=openai_api_key)
        self.report_dir = "technique_reports"
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
        self.initialize_database()
        logger.info("MITRE ATT&CK Suricata The system has been reset.")

# Initialize database (create table)
    def initialize_database(self):
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS suricata_rules (
            technique_id TEXT PRIMARY KEY,
            rule_content TEXT,
            is_valid BOOLEAN,
            last_updated TEXT
        )
        ''')
        self.conn.commit()

 # Generate SID from technical ID  
    def generate_sid(self, technique_id: str) -> int:
        numeric_part = re.sub(r'\D', '', technique_id)
        base_sid = int(numeric_part) % 1000000
        return 3000000 + base_sid

 # Create Suricata rule based on technology ID  
    def generate_suricata_rule(self, technique_id):
        logger.info(f"Creating Suricata rule for technology {technique_id}...")
        prompt = self.generate_prompt(technique_id)
        response = self.chat_model.invoke(prompt.messages)
        rule_content = response.content.strip()
        logger.debug(f"Original rule generated by GPT-4o-mini:\n{rule_content}")
        rule_content = self.post_process_rule(rule_content, technique_id)
        logger.debug(f"Post-processed rule:\n{rule_content}")
        logger.info(f"Suricata rule creation completed for technology {technique_id}")
        return rule_content

    # Post-processing for created rules
    def post_process_rule(self, rule_content: str, technique_id: str) -> str:
        logger.debug(f"Original rule content:\n{rule_content}")

     # 1. Remove comments  
        rule_content = re.sub(r'#.*', '', rule_content).strip()

      # 2. SID creation and assignment 
        sid_pattern = re.compile(r'sid:\s*\d+;')
        existing_sid = sid_pattern.search(rule_content)
        new_sid = self.generate_sid(technique_id)
        if existing_sid:
            rule_content = sid_pattern.sub(f'sid:{new_sid};', rule_content)
        else:
            rule_content = re.sub(r'\)\s*$', f' sid:{new_sid};)', rule_content)

      # 3. Check and set rev value
        if 'rev:' not in rule_content:
            rule_content = re.sub(r'\)\s*$', ' rev:1;)', rule_content)

      # 4. Check and set classtype  
        if 'classtype:' not in rule_content:
            rule_content = re.sub(r'\)\s*$', ' classtype:trojan-activity;)', rule_content)

       # 5. Check and format reference options
        rule_content = re.sub(r'reference:.*?;', '', rule_content)
        rule_content = re.sub(r'\)\s*$', f' reference:url,https://attack.mitre.org/techniques/{technique_id}/;)', rule_content)

      # 6. Add Evasion Resistance
        if 'nocase;' not in rule_content:
            rule_content = re.sub(r'(\bcontent:[^;]+;)', r'\1 nocase;', rule_content)

      # 7. Check and limit the number of fast_pattern usages  
        fast_pattern_count = rule_content.count('fast_pattern;')
        if fast_pattern_count > 1:
            rule_content = rule_content.replace('fast_pattern;', '', fast_pattern_count - 1)

       # 8. Header validation and auto-correction
        logger.debug(f"Checking rule header for validity: {rule_content}")

        header_pattern = re.compile(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip|http|ftp|tls|smb|dns|file)\s+any\s+any\s+->\s+any\s+any\s+\(.*\)$', re.IGNORECASE)
        if not header_pattern.match(rule_content):
            logger.error(f"Invalid rule header detected: {rule_content}")

          # Try replacing with default header 
            try:
                parts = rule_content.split('(')
                if len(parts) > 1:
                    options = '(' + '('.join(parts[1:])
                    corrected_rule = f"alert tcp any any -> any any {options}"
                    if header_pattern.match(corrected_rule):
                        logger.info(f"Corrected rule header with default: {corrected_rule}")
                        rule_content = corrected_rule
                    else:
                        raise ValueError("Unable to correct rule header using default.")
                else:
                    raise ValueError("Rule format is too unexpected to correct.")
            except Exception as e:
                logger.error(f"Failed to correct rule header: {rule_content}. Generating a basic default rule.")
             # Create default rule 
                rule_content = f"alert tcp any any -> any any (msg:\"Default rule for {technique_id}\"; sid:{self.generate_sid(technique_id)}; rev:1; classtype:trojan-activity; reference:url,https://attack.mitre.org/techniques/{technique_id}/;)"
                logger.debug(f"Generated basic default rule: {rule_content}")

     # 9. Performance optimization: remove excessive content or pcre and add fast_pattern
        content_matches = re.findall(r'content:', rule_content)
        pcre_matches = re.findall(r'pcre:', rule_content)
        if len(content_matches) > 3 or len(pcre_matches) > 3:
            rule_content = re.sub(r'(content|pcre):[^;]+;', '', rule_content, len(content_matches) - 3)

       # Automatically add fast_pattern option 
        if 'content:' in rule_content and 'fast_pattern;' not in rule_content:
            rule_content = re.sub(r'(content:[^;]+;)', r'\1 fast_pattern;', rule_content)

       # 10. Clean up spaces and unnecessary semicolons 
        rule_content = re.sub(r'\s{2,}', ' ', rule_content)  # remove double spaces
        rule_content = re.sub(r';\s*;', ';', rule_content) # Remove double semicolons
        rule_content = rule_content.strip()

        logger.debug(f"Final processed rule:\n{rule_content}")
        return rule_content

# Suricata grammar verification
    def validate_syntax(self, rule_content):
        logger.info("Suricata 7.0 규칙 문법 검증 중...")
        logger.debug(f"검증 중인 규칙 내용:\n{rule_content}")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as temp_file:
            temp_file.write(rule_content)
            temp_file_path = temp_file.name

        try:
            result = subprocess.run(
                [self.suricata_path, '-T', '-c', '/opt/homebrew/etc/suricata/suricata.yaml', '-S', temp_file_path],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Grammar verification passed")
            return True, "Syntax validation passed"
        except subprocess.CalledProcessError as e:
            error_message = e.stderr
            logger.error(f"Grammar verification failed. Error message:\n{error_message}")
            return False, f"Syntax validation failed: {error_message}"
        finally:
            os.unlink(temp_file_path)

   # Verification of generated rules (grammar, flexibility, simulation)
    def validate_rule(self, technique_id, rule_content):
        syntax_valid, syntax_message = self.validate_syntax(rule_content)
        
        validator = SuricataRuleValidator(technique_id, self.get_technique_name(technique_id))
        flex_valid, flex_result = validator.validate(rule_content)
        
        simulator = SuricataSimulator()
        sim_success = False
        sim_alerts = []
        
        if flex_valid:
            try:
                rule = SuricataRule(flex_result["header"], flex_result["options"])
                simulator.load_rule(rule)
                
            # Create a test packet containing all content options    
                contents = [rule.options[key] for key in rule.options if key.startswith('content')]
                test_packet = {
                    "protocol": rule.header.split()[1],
                    "payload": f"Test payload with {' and '.join(contents)}"
                }
                
                logger.debug(f"Testing with packet: {test_packet}")
                sim_success, sim_alerts = simulator.simulate_traffic(test_packet)
                logger.debug(f"Simulation success: {sim_success}, alerts: {sim_alerts}")
            except Exception as e:
                logger.error(f"Simulation error: {str(e)}")
                sim_alerts = [f"Simulation error: {str(e)}"]
        
        is_valid = syntax_valid and flex_valid and sim_success
        return is_valid, {
            "syntax_validation": syntax_message,
            "flexible_validation": validator.get_report(),
            "simulation_success": sim_success,
            "simulation_alerts": sim_alerts
        }

   # Generate and process Suricata rules for a given skill
    def process_technique(self, technique):
        technique_id, name, description, detection = technique
        report_filename = f"{self.report_dir}/technique_{technique_id}_report.txt"
        
        if os.path.exists(report_filename):
            logger.info(f"Technique {technique_id} already processed. Skipping.")
            with open(report_filename, 'r') as f:
                report_content = f.read()
            is_valid = "Valid: Yes" in report_content
            return is_valid, None

        logger.info(f"Processing technique: {name} ({technique_id})")

        suricata_rule = self.generate_suricata_rule(technique_id)
        is_valid, validation_result = self.validate_rule(technique_id, suricata_rule)

        last_updated = datetime.now().isoformat()
        
        self.cursor.execute('''
        INSERT OR REPLACE INTO suricata_rules (technique_id, rule_content, is_valid, last_updated)
        VALUES (?, ?, ?, ?)
        ''', (technique_id, suricata_rule, is_valid, last_updated))
        
        self.conn.commit()
        logger.info(f"Technique {technique_id} processed: {'Valid' if is_valid else 'Invalid'}")
        
        report = self.generate_technique_report(technique_id, name, description, detection, is_valid, validation_result, suricata_rule)
        self.save_technique_report(technique_id, report)
        
        return is_valid, validation_result

  # Handles all network related technologies 
    def process_all_techniques(self):
        logger.info("Processing all network-related techniques")
        techniques = self.get_network_techniques()
        results = []
        for index, technique in enumerate(techniques, 1):
            is_valid, validation_result = self.process_technique(technique)
            results.append({
                "technique_id": technique[0],
                "name": technique[1],
                "is_valid": is_valid,
                "validation_result": validation_result
            })
            logger.info(f"Processed {index}/{len(techniques)} techniques")
        logger.info("All techniques processed")
        return results

# Filter network-related technologies
    def get_network_techniques(self):
        logger.info("Filtering network-related technologies...")
        network_keywords = ["network", "traffic", "packet", "connection", "flow", "port", "protocol"]
        
        query = '''
        SELECT id, name, description, detection 
        FROM techniques 
        WHERE ''' + ' OR '.join([f"lower(description) LIKE ? OR lower(detection) LIKE ?" for _ in network_keywords])
        
        params = ['%' + keyword.lower() + '%' for keyword in network_keywords for _ in range(2)]
        
        self.cursor.execute(query, params)
        network_techniques = self.cursor.fetchall()
        
        logger.info(f"Found {len(network_techniques)} network-related techniques")
        return network_techniques

  # Generate reports on skills 
    def generate_technique_report(self, technique_id, name, description, detection, is_valid, validation_result, suricata_rule):
        report = f"Technique Report: {name} ({technique_id})\n"
        report += "=" * 50 + "\n\n"
        
        report += "ATT&CK Technique Details:\n"
        report += f"Name: {name}\n"
        report += f"ID: {technique_id}\n"
        report += f"Description: {description}\n"
        report += f"Detection: {detection}\n\n"
        
        report += "Generated Suricata Rule:\n"
        report += "```\n"
        report += suricata_rule
        report += "\n```\n\n"
        
        report += f"Valid: {'Yes' if is_valid else 'No'}\n"
        
        # Syntax Validation
        report += "\nSyntax Validation:\n"
        report += "=" * 50 + "\n"
        report += f"{validation_result['syntax_validation']}\n"

        # Simulator Validation Results
        report += "\nSimulator Validation:\n"
        report += "=" * 50 + "\n"
        if validation_result['simulation_success']:
            report += "Simulation passed successfully.\n"
        else:
            report += "Simulation failed.\n"
        
        if validation_result['simulation_alerts']:
            report += "Simulation Alerts:\n"
            for alert in validation_result['simulation_alerts']:
                report += f"- {alert}\n"

        report += "\nFlexible Validation:\n"
        report += "=" * 50 + "\n"
        report += f"{validation_result['flexible_validation']}\n"

        report += "-" * 50 + "\n"
        return report

 # Save as technical report file
    def save_technique_report(self, technique_id, report):
        filename = f"{self.report_dir}/technique_{technique_id}_report.txt"
        with open(filename, "w") as f:
            f.write(report)
        logger.info(f"Saved report for technique {technique_id}")

# Generate summary report
    def generate_summary_report(self, results):
        total_techniques = len(results)
        valid_rules = sum(1 for r in results if r["is_valid"])
        skipped_techniques = sum(1 for r in results if r["validation_result"] is None)

        report = "MITRE ATT&CK Suricata Rule Generation Summary Report\n"
        report += "=" * 50 + "\n\n"
        report += f"Total techniques processed: {total_techniques}\n"
        report += f"Valid rules: {valid_rules}\n"
        report += f"Invalid rules: {total_techniques - valid_rules - skipped_techniques}\n"
        report += f"Skipped techniques: {skipped_techniques}\n\n"

        for result in results:
            report += f"Technique: {result['name']} ({result['technique_id']})\n"
            if result['validation_result'] is None:
                report += "Status: Skipped (Already processed)\n"
            else:
                report += f"Valid: {'Yes' if result['is_valid'] else 'No'}\n"
                report += f"Details: See individual report file for technique_{result['technique_id']}_report.txt\n"
            report += "-" * 30 + "\n\n"

        return report

   # Get skill name
    def get_technique_name(self, technique_id):
        self.cursor.execute('SELECT name FROM techniques WHERE id = ?', (technique_id,))
        result = self.cursor.fetchone()
        return result[0] if result else "Unknown Technique"

  # Create prompt for rule creation 
    def generate_prompt(self, technique_id):
        self.cursor.execute('SELECT name, description, detection FROM techniques WHERE id = ?', (technique_id,))
        technique = self.cursor.fetchone()
        
        if not technique:
            raise ValueError(f"Technique with ID {technique_id} not found")
        
        name, description, detection = technique

        prompt = f"""As a cybersecurity expert, generate a Suricata 7.0 rule for the following MITRE ATT&CK technique:

        Technique: {name}
        ID: {technique_id}
        Description: {description}
        Detection Guidance: {detection}

        **Requirements for the Suricata Rule:**

        1. **Header**:
        - Use a valid action (e.g., alert, drop).
        - Specify a valid protocol (e.g., tcp, udp, icmp, http, file).
        - Use "any" for source and destination IP addresses and ports unless specific values are needed.

        2. **Rule Options**:
        - Include `msg` to describe the rule, encapsulated in double quotes.
        - Ensure at least one `content` or `pcre` option is included, but avoid excessive use to minimize performance impact.
        - **Use `fast_pattern` on only one `content` option within the rule**.
        - Use the `reference` option to link to the MITRE ATT&CK technique page in the format: `reference:url,https://attack.mitre.org/techniques/{technique_id}/;`.
        - Assign a unique `sid` in the format `sid:<unique_number>;` (e.g., `sid:1000001;`).
        - Set `rev:1;` as the revision number.
        - Use an appropriate `classtype` (e.g., `trojan-activity`, `attempted-admin`).
        - Avoid using `priority` or other non-standard Suricata options unless necessary.
        - Ensure all options are correctly terminated with semicolons and properly spaced.

        3. **Evasion Resistance**:
        - Ensure that the rule is resistant to simple evasion techniques, such as case variations or slight modifications in attack patterns.
        - Consider adding `nocase;` or similar options where applicable.

        4. **Security Threat Analysis**:
        - Analyze the specific characteristics of the given security threat, focusing on known attack vectors, evasion techniques, and common payload patterns.
        - Consider any indicators of compromise (IoCs) that are commonly associated with this technique.
        - Include patterns or behaviors that would be indicative of this threat in a network environment.

        5. **Protocol-Specific Considerations**:
        - Identify the network protocols typically used by this technique (e.g., TCP, UDP, HTTP, DNS) and tailor the rule to detect anomalies or suspicious activities within those protocols.
        - For each relevant protocol, include specific checks (e.g., unusual port usage, malformed packets, or unexpected protocol commands).

        6. **Application-Specific Analysis**:
        - Determine if this technique targets or exploits specific applications or services (e.g., web servers, database servers, email servers).
        - Include content or pcre patterns to detect known malicious payloads or commands specific to these applications.
        - Tailor the rule to monitor traffic associated with these applications, identifying unusual behaviors or anomalies.
            
        7. **Formatting**:
        - Keep the rule on a single line with no line breaks.
        - Do not include comments or markdown formatting in the rule.

        Generate the Suricata rule based on the above guidelines."""
                
        return ChatPromptTemplate.from_messages([HumanMessage(content=prompt)])

   # Close database connection
    def close(self):
        self.conn.close()
        logger.info("The database connection has been terminated.")

# Main function (initializes the system and handles all technology)
def main():
    openai_api_key = "YOUR_OPENAI_API_TOKEN"

    system = MitreAttackSuricataSystem(openai_api_key)

 # Handles all network related technologies and creates Suricata rules 
    results = system.process_all_techniques()

# Generate summary report
    summary_report = system.generate_summary_report(results)
    print(summary_report)

 # Save summary report to file 
    with open("mitre_attack_suricata_summary_report.txt", "w") as f:
        f.write(summary_report)

    system.close()

# Execute main function
if __name__ == "__main__":
    main()
