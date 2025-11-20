# Task 2: Computer Network Security

import sys
import re
import os


RULES_FILE = "firewall_rules.txt"

# Represents a firewall rule
class FirewallRule:
    def __init__(self, rule_number, direction, address):
        self.rule_number = rule_number
        self.direction = direction
        self.address = address
    
    def __str__(self):
        dir_str = self.direction if self.direction != "both" else "in/out"
        return f"Rule {self.rule_number}: {dir_str} {self.address}"

# Manage firewall rules
class FirewallManager:
    def __init__(self):
        self.rules = []
        self.load_rules()
    
    # load rules from file
    def load_rules(self):
        if os.path.exists(RULES_FILE):
            try:
                # Reading text file with one rule per line:
                # format: rule_number|direction|address
                rules = []
                with open(RULES_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split('|')
                        if len(parts) != 3:
                            continue
                        try:
                            rn = int(parts[0])
                        except:
                            continue
                        direction = parts[1]
                        address = parts[2]
                        rules.append(FirewallRule(rn, direction, address))
                self.rules = rules
            except Exception:
                # If text reading fails for any reason, fall back to an empty list
                self.rules = []
    
    # save rules to file
    def save_rules(self):
        try:
            # Save one rule per line
            # format: rule_number|direction|address
            with open(RULES_FILE, 'w', encoding='utf-8') as f:
                for r in self.rules:
                    line = f"{r.rule_number}|{r.direction}|{r.address}\n"
                    f.write(line)
        except Exception:
            pass
    
    # Add a new rule
    def add_rule(self, rule_number, direction, address):
        if rule_number is None:
            rule_number = 1
        if direction is None:
            direction = "both"
        
        new_rule = FirewallRule(rule_number, direction, address)
        
        # Insert at correct position
        inserted = False
        for i, rule in enumerate(self.rules):
            if rule.rule_number >= rule_number:
                self.rules.insert(i, new_rule)
                # Renumber following rules
                for j in range(i + 1, len(self.rules)):
                    self.rules[j].rule_number += 1
                inserted = True
                break
        
        if not inserted:
            self.rules.append(new_rule)
        
        self.save_rules()
    
    # Remove a rule
    def remove_rule(self, rule_number, direction):
        # Find rule
        rule_index = None
        for i, rule in enumerate(self.rules):
            if rule.rule_number == rule_number:
                rule_index = i
                break
        
        if rule_index is None:
            print(f"Error: Rule {rule_number} does not exist")
            return
        
        rule = self.rules[rule_index]
        
        # Remove entire rule if no direction specified
        if direction is None:
            self.rules.pop(rule_index)
            # Renumber following rules
            for i in range(rule_index, len(self.rules)):
                self.rules[i].rule_number -= 1
            self.save_rules()
            return
        
        # Remove one direction from bidirectional rule
        if rule.direction == "both":
            rule.direction = "out" if direction == "in" else "in"
            self.save_rules()
            return
        
        # Remove single-direction rule
        if rule.direction == direction:
            self.rules.pop(rule_index)
            for i in range(rule_index, len(self.rules)):
                self.rules[i].rule_number -= 1
            self.save_rules()
            return
        
        print(f"Error: Rule {rule_number} does not have {direction} direction")
    
    # List rules with optional filters
    def list_rules(self, rule_number=None, direction=None, address=None):
        if not self.rules:
            print("No firewall rules configured")
            return
        
        matching = []
        for rule in self.rules:
            # Filter by rule number
            if rule_number and rule.rule_number != rule_number:
                continue
            # Filter by direction
            if direction and not self._matches_direction(rule, direction):
                continue
            # Filter by address
            if address and not self._matches_address(rule, address):
                continue
            matching.append(rule)
        
        if not matching:
            print("No rules match the specified criteria")
            return
        
        for rule in matching:
            print(rule)
    
    # Check if rule matches direction filter.
    def _matches_direction(self, rule, direction):
        if rule.direction == "both":
            return True
        return rule.direction == direction
    
    # Check if address overlaps with rule.
    def _matches_address(self, rule, address):
        start1, end1 = self._parse_range(rule.address)
        start2, end2 = self._parse_range(address)
        return not (end1 < start2 or start1 > end2)
    
    # Parse address into start and end integers.
    def _parse_range(self, addr):
        if '-' in addr:
            start, end = addr.split('-')
            return self._ip_to_int(start), self._ip_to_int(end)
        else:
            ip_int = self._ip_to_int(addr)
            return ip_int, ip_int
    
    # Convert IP address to integer.
    def _ip_to_int(self, ip):
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

# Validate IPv4 address (10.0.0.0-10.0.0.255).
def validate_ip(ip):
    pattern = r'^10\.0\.0\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if not match:
        return False
    last_octet = int(match.group(1))
    return 0 <= last_octet <= 255

# Parse and validate address or range.
def parse_address(addr_str):
    if '-' in addr_str:
        parts = addr_str.split('-')
        if len(parts) != 2:
            raise ValueError(f"Invalid address range format: {addr_str}")
        
        start = parts[0].strip()
        end = parts[1].strip()
        
        if not validate_ip(start) or not validate_ip(end):
            raise ValueError(f"Invalid IP address in range")
        
        # Check start <= end
        start_int = sum(int(x) << (8 * (3 - i)) for i, x in enumerate(start.split('.')))
        end_int = sum(int(x) << (8 * (3 - i)) for i, x in enumerate(end.split('.')))
        if start_int > end_int:
            raise ValueError("Start address must be <= end address")
        
        return addr_str
    else:
        addr = addr_str.strip()
        if not validate_ip(addr):
            raise ValueError(f"Invalid IP address: {addr}")
        return addr

# Parse command line arguments.
def parse_command(args):
    if len(args) == 0:
        raise ValueError("No command specified")
    
    command = args[0].lower()
    
    if command not in ['add', 'remove', 'list']:
        raise ValueError(f"Unknown command: {command}")
    
    parsed = {
        'command': command,
        'rule_number': None,
        'direction': None,
        'address': None
    }
    
    i = 1
    while i < len(args):
        arg = args[i]
        
        if arg in ['-in', '-out']:
            if parsed['direction']:
                raise ValueError("Direction specified multiple times")
            parsed['direction'] = 'in' if arg == '-in' else 'out'
        
        elif arg.isdigit():
            if parsed['rule_number']:
                raise ValueError("Rule number specified multiple times")
            rule_num = int(arg)
            if rule_num < 1:
                raise ValueError("Rule number must be >= 1")
            parsed['rule_number'] = rule_num
        
        elif re.match(r'^\d+\.\d+\.\d+\.\d+', arg):
            if parsed['address']:
                raise ValueError("Address specified multiple times")
            parsed['address'] = parse_address(arg)
        
        else:
            raise ValueError(f"Unknown argument: {arg}")
        
        i += 1
    
    # Validate command requirements
    if command == 'add' and not parsed['address']:
        raise ValueError("'add' command requires an IP address")
    if command == 'remove' and not parsed['rule_number']:
        raise ValueError("'remove' command requires a rule number")
    
    return parsed


# Global manager to persist rules across commands
manager = FirewallManager()


def main():
    global manager
    
    if len(sys.argv) == 1:
        print("Usage: python firewall.py <command> [options]")
        print("Commands: add, remove, list")
        print("Example: python firewall.py add 1 -in 10.0.0.1")
        return
    
    try:
        # Parse and execute command
        parsed = parse_command(sys.argv[1:])
        
        if parsed['command'] == 'add':
            manager.add_rule(parsed['rule_number'], parsed['direction'], parsed['address'])
        
        elif parsed['command'] == 'remove':
            manager.remove_rule(parsed['rule_number'], parsed['direction'])
        
        elif parsed['command'] == 'list':
            manager.list_rules(parsed['rule_number'], parsed['direction'], parsed['address'])
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
