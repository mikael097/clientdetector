import scapy.all as scapy
import argparse


class NetworkScanner:
    def __init__(self):
        pass

    @staticmethod
    def get_argument_list():
        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--range", dest="Range", help="Target IP/Range")
        option = parser.parse_args()
        return option

    @staticmethod
    def scan(ip):
        arp_request_packet_object = scapy.ARP(pdst=ip)
        broadcast_ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast_ether/arp_request_packet_object
        answered_list = scapy.srp(arp_packet, timeout=1, verbose=False)[0]
        return answered_list

    @staticmethod
    def display(answered_list):
        print("IP\t\t\t\tMAC")
        print("-----------------------------------------")
        client_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "MAC": element[1].hwsrc}
            client_list.append(client_dict)
        for ele in client_list:
            print(ele["ip"], "\t\t", ele["MAC"])


obj = NetworkScanner()
options = obj.get_argument_list()
result = obj.scan(options.Range)
obj.display(result)
