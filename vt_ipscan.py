import sys
import time
import csv
import requests
import argparse

logo ="""
█░█ █ █▀█ ▀█▀ █░█ █▀   ▀█▀ █▀█ ▀█▀ ▄▀█ █░░   █ █▀█   █▀ █▀▀ ▄▀█ █▄░█
▀▄▀ █ █▀▄ ░█░ █▄█ ▄█   ░█░ █▄█ ░█░ █▀█ █▄▄   █ █▀▀   ▄█ █▄▄ █▀█ █░▀█"""


API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
csv_file = "ip_scan_report.csv"
header_write = 0

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    END_COLOR = '\033[0m'


class IPScan:

    def __init__(self, ip_list, API_KEY):
        self.API_KEY = API_KEY
        self.header = {
            "Accept": "application/json",
            "User-Agent": "VT_IPScan v.1.0",
            "x-apikey": API_KEY
        }
        self.ip_list = ip_list
        self.ip_count = 0

    def info(self):
        print(logo)
        print("Version: VT_IPScan v.1.0")
        print()
        print(f"{Colors.BLUE}Get brief information about the analysis of the IP{Colors.END_COLOR}")

    def still_next_ip(self):
        return self.ip_count < len(self.ip_list)

    def analyse(self):
        current_ip = self.ip_list[ self.ip_count ]
        self.ip_count += 1
        scan_url = API_URL + current_ip
        try:
            response = requests.get(scan_url, headers=self.header)
        except:
            print(f"{Colors.RED}Failed to get info, cannot request API{Colors.END_COLOR}")
            sys.exit()
        else:
            if response.status_code == 200:
                vt_result = response.json()
                country = vt_result.get("data").get("attributes").get("country")
                as_owner = vt_result.get("data").get("attributes").get("as_owner")
                last_analysis_stats = vt_result.get("data").get("attributes").get("last_analysis_stats")
                malicious = last_analysis_stats["malicious"]
                suspicious = last_analysis_stats["suspicious"]
                undetected = last_analysis_stats["undetected"]
                print("==================================================")
                print(f"IP address:{current_ip}")
                print(f"Country: {country}")
                print(f"AS_Owner: {as_owner}")
                print(f"{Colors.RED}Malicious:{malicious}{Colors.END_COLOR}")
                print(f"{Colors.RED}Suspicious:{suspicious}{Colors.END_COLOR}")
                print(f"{Colors.YELLOW}Undetected:{undetected}{Colors.END_COLOR}")

            else:
                print(f"{Colors.BLUE}Failed to analyse the IP{Colors.END_COLOR}")
            if self.ip_count >= len(self.ip_list):
                print(Colors.GREEN + "Successfully analyse!!" + Colors.END_COLOR)
            self.report(current_ip,malicious,suspicious,undetected,country)

    def report(self, ip, malicious, suspicious, undetected, country):
        global csv_file
        field_name = ['IP', 'Malicious', 'Suspicious', 'Undetected', 'Country']
        global header_write
        with open(csv_file,'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=field_name)
            if header_write == 0:
                writer.writeheader()
                writer.writerow({'IP': ip, 'Malicious': malicious, 'Suspicious': suspicious, 'Undetected': undetected,
                                 'Country': country})
                header_write = 1
            else:
                writer.writerow({'IP': ip, 'Malicious': malicious,'Suspicious': suspicious, 'Undetected': undetected,
                                 'Country': country})


if __name__ == "__main__":
    ip_data = []
    parser = argparse.ArgumentParser(description="Analyse IP address in Virus Total")
    parser.add_argument('-i', '--ip', type=str, metavar='', help='Only one IP address')
    parser.add_argument('-f', '--file', type=str, metavar='', help="IP list")
    parser.add_argument('-o', '--output', type=str, metavar='', help="The report file name(.csv)")
    args = parser.parse_args()
    if args.ip and args.file:
        print("Error! Please enter one argument (ip, file) ")
        sys.exit()
    elif args.ip:
        ip_data.append(args.ip)
    elif args.file:
        ip_file = open(args.file).read()
        files = ip_file.splitlines()
        for file in files:
            ip_data.append(file)
    if args.output:
        csv_file = args.output

    if len(sys.argv) == 1:
        print("Please use argument -h for usage")
        sys.exit()
    api_key = input("Paste your Virus Total API KEY:")
    scan = IPScan(ip_data,api_key)
    scan.info()
    start_time = time.strftime("%H:%M:%S", time.gmtime(time.time()))
    print(f"Start time: {start_time}")
    while scan.still_next_ip():
        scan.analyse()
    end_time = time.strftime("%H:%M:%S", time.gmtime(time.time()))
    print(f"End time: {end_time}")
