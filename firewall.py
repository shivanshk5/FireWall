# Assuming valid inputs according to spec. Otherwise, need more checks to check if valid input
class Firewall:
	def __init__(self, path):
		self.path = path
		self.rules = {"inbound": {"udp": set(), "tcp": set()}, "outbound": {"udp": set(), "tcp": set()}}
		with open(self.path, "r") as f:
			for each_rule in f:
				rule = Rule(each_rule)
				self.rules[rule.direction][rule.protocol].add(rule)				

	def accept_packet(self, direction, protocol, port, ip_address):
		for rule in self.rules[direction][protocol]:
			if rule.passes(direction, protocol, port, ip_address):
				return True
			return False


class Rule:
	def __init__(self, rules_attrs):
		split_attrs = rules_attrs.split(",")
		attrs = [attr.strip() for attr in split_attrs]
		self.direction = attrs[0]
		self.protocol = attrs[1]
		self.port = Range_Check(attrs[2])
		self.ip = Range_Check(attrs[3].strip("\n").strip("\r"))

	def passes(self, direction, protocol, port, ip_address):
		return self.direction == direction and self.protocol == protocol and self.port.passes(str(port)) and self.ip.passes(ip_address)


# Removing redundancy of code for Port and IP
class Range_Check:
	def __init__(self, valid_attr):
		self.attr = valid_attr.split("-") # If "-" exists, then there should be 2 elems in attr. Otherwise, 1 element

	def passes(self, attr):
		if len(self.attr) == 1:
			return self.attr[0] == attr
		return self.attr[0] <= attr <= self.attr[1] # Checking range of attr



# # Initial approach through naive solution of going through all the rules and storing in a list
# # Then checking if package satisifies one of the rules
# # Time complexity and space complexity is O(n)
# class Firewall:
# 	def __init__(self, path):
# 		self.path = path
# 		self.rules = []
# 		with open(self.path, "r") as f:
# 			for each_rule in f:
# 				self.rules.append(Rule(each_rule))				

# 	def accept_packet(direction, protocol, port, ip_address):
# 		for rule in self.rules:
# 			if rule.passes(direction, protocol, port, ip_address):
# 				return True
# 			return False


# class Rule:
# 	def __init__(self, rules_attrs):
# 		split_attrs = rules_attrs.split(",")
# 		attrs = [attr.strip() for attr in split_attrs]
# 		self.direction = attrs[0]
# 		self.protocol = attrs[1]
# 		self.port = Port(attrs[2])
# 		self.ip = IP(attrs[3])

# 	def passes(self, direction, protocol, port, ip_address):
# 		return self.direction == direction and self.protocol == protocol 
# 			and self.port.passes(str(port)) and self.ip.passes(ip_address)


# class Port:
# 	def __init__(self, valid_ports):
# 		self.port = valid_ports.split("-") # If "-" exists, then there should be 2 elems in port. Otherwise, 1 element

# 	def passes(self, port):
# 		if len(self.port) == 1:
# 			return self.port == port
# 		return self.port[0] <= port <= self.port[1] # Checking range of port


# class IP:
# 	def __init__(self, valid_ip):
# 		self.ip = valid_ip.split("-") # If "-" exists, then there should be 2 elems in ip. Otherwise, 1 element

# 	def passes(self, ip):
# 		if len(self.ip) == 1:
# 			return self.ip == ip
# 		return self.ip[0] <= ip <= self.ip[1] # Checking range of ip
