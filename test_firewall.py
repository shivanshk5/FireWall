import firewall
# import pdb
def test_firewall_rules():
	firewall_obj = firewall.Firewall("tests/test1.csv")
	#pdb.set_trace()
	assert firewall_obj.rules == ['inbound,tcp,80,192.168.1.2\r\n', 
									'outbound,tcp,10000-20000,192.168.10.11\r\n', 
									'inbound,udp,53,192.168.1.1-192.168.2.5\r\n', 
									'outbound,udp,1000-2000,52.12.48.92']

def test_accept_packet():
	firewall_obj = firewall.Firewall("tests/test1.csv")
	#pdb.set_trace()
	assert firewall_obj.accept_packet("inbound", "tcp", 80, "192.168.1.2") == True
	assert firewall_obj.accept_packet("inbound", "tcp", 80, "192.168.1.3") == False

	assert firewall_obj.accept_packet("inbound", "udp", 53, "192.168.2.0") == True
	assert firewall_obj.accept_packet("inbound", "udp", 53, "192.168.2.7") == False

	assert firewall_obj.accept_packet("outbound", "tcp", 11000, "192.168.10.11") == True
	assert firewall_obj.accept_packet("outbound", "tcp", 8000, "192.168.10.11") == False

	assert firewall_obj.accept_packet("outbound", "udp", 1500, "52.12.48.92") == True
	assert firewall_obj.accept_packet("outbound", "udp", 2001, "52.12.48.92") == False

	# Checking on bounds
	assert firewall_obj.accept_packet("inbound", "udp", 80, "192.168.1.2") == False
	assert firewall_obj.accept_packet("inbound", "tcp", 53, "192.168.2.0") == False
	assert firewall_obj.accept_packet("outbound", "tcp", 10000, "192.168.10.11") == True
	assert firewall_obj.accept_packet("outbound", "tcp", 20000, "192.168.10.11") == True
	assert firewall_obj.accept_packet("outbound", "udp", 1000, "52.12.48.92") == True
	assert firewall_obj.accept_packet("outbound", "udp", 2000, "52.12.48.92") == True

if __name__ == "__main__":
	# Used pdb to see rules and to check whether rules were imported properly from csv file for test_firewall_rules
	# test_firewall_rules()
	test_accept_packet()
	print("Passed")