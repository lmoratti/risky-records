import argparse
import ipaddress
import dns.asyncquery
import dns.message
import dns.rdataclass
import dns.rdatatype
import json
from json import JSONEncoder 
import re
import dns.rdtypes
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from time import time
import asyncio
import aiohttp
import requests


console = Console()

parser = argparse.ArgumentParser(description="Check domain A records against AWS IP ranges.")
parser.add_argument('--file',          type=str, help="Path to the file containing domain names.")
parser.add_argument('--services',      type=str, help="AWS service name to filter IP ranges by. Default is EC2, S3.", default="EC2,S3" )
parser.add_argument('--dns-server',    type=str, help="DNS server to query for A records. Default is 8.8.8.8.",   default="8.8.8.8")
parser.add_argument('--owned-ips',     type=str, help="Path to the file containing user-owned IP addresses.")
parser.add_argument('--owned-buckets', type=str, help="Path to the file containing user-owned buckets.")
parser.add_argument('--output',        type=str, help="Filename to store JSON output of all risky records.")
parser.add_argument('--print-summary',           help="Print summary of risky records.", action='store_true')

args = parser.parse_args()

def filter_ranges_by_service( json_ranges: dict, service_name: str=None,) -> dict:
        """
        Reduce the IP-Ranges JSON from AWS based on service names they support,
        then return it as a dictionary.
        """
        filtered_range = {}
        for prefix in json_ranges["prefixes"]:
            if service_name and prefix["service"] == service_name:
                filtered_range[ipaddress.IPv4Network(prefix["ip_prefix"])] = prefix
        return filtered_range

def read_list_file(path: str) -> list:
    """
    Read list in from a file-path. 
    File should be formatted with a items on each newline of the file.
    Returns a list of items names.
    """
    with open(path, 'r') as file:
        lines_list = [line.strip() for line in file.readlines()]
    return lines_list

def write_json_file(path: str, domains: list) -> None:
    """
    Write to file in JSON format. 
    """
    risky_records =  [domain.risky_records for domain in domains if len(domain.risky_records) > 0]
    with open(path, 'w') as outfile:
       json.dump(risky_records, outfile, indent=4, cls=RiskyRecordEncoder)



class Domain():
    def __init__(self: "Domain", domain_name: str, service_ranges: dict, dns_server: str = "8.8.8.8", query_types: list=[dns.rdatatype.A, dns.rdatatype.CNAME], user_owned_buckets: set=None, user_owned_ips: set=None) -> None:
        self.domain_name:        str  = domain_name
        self.dns_server:         str  = dns_server
        self.query_types:        list = query_types
        self.service_ranges:     dict = service_ranges
        self.records:            list = []
        self.risky_records:      list = []
        self.user_owned_buckets: set  = user_owned_buckets
        self.user_owned_ips:     set  = user_owned_ips
    
    async def _check_domain_records(self: "Domain", dns_server: str = "8.8.8.8", timeout: float=10) -> None:
        """"
        Async Query a DNS server for A and CNAME records. Uses 8.8.8.8 as a default. 
        """
        query_name = dns.name.from_text(self.domain_name)

        for query_type in self.query_types:
            query          = dns.message.make_query(query_name, query_type)
            query_response = await dns.asyncquery.udp(query, dns_server, timeout=timeout)

            if query_response.answer:
                for record_set in query_response.answer:
                    for record in record_set:
                        self.records.append(RiskyRecord.handle_record(record, self))


    async def process_domain(self: "Domain") -> list:
        """Process a single domain to check its records and return risky records if found."""
        await self._check_domain_records()

        for record in self.records:
            if record.determine_risk():
                console.print(f"{record}")
                self.risky_records.append(record)

        return self.risky_records


class RiskyRecord:
    TYPE = None

    def __init__(self: "RiskyRecord", points_to: str, domain: Domain) -> None:
        self.domain:    Domain = domain
        self.points_to: str    = str(points_to)
        self.risk:      str    = None
        self.info:      str    = None
        self.aws_info:  dict   = {}


    @classmethod
    def handle_record(cls: type, record: "DNSRecord", domain: Domain) -> "RiskyRecord":
        for klass in cls.__subclasses__():
            if klass.TYPE == record.rdtype:
                return klass(record, domain)


    def get_info(self):
        raise NotImplementedError

    def determine_risk(self) -> str:
        raise NotImplementedError


    def __repr__(self: "RiskyRecord")-> str:
        return f'<{self.__class__.__name__}: domain={self.domain.domain_name}, record_type={self.TYPE}, points_to={self.points_to}, risk={self.risk}, info={self.info}>'


    def __str__(self):
        if not self.risk:
            return

        if self.risk == "WARN":
            color = "yellow"
        elif self.risk == "RISKY":
            color = "red"

        return f"\t[{color}][{self.risk}] {self.domain.domain_name} has a DNS {self.record_type} Record pointed at {self.points_to}.[/{color}]"
    



        
class RiskyRecordA(RiskyRecord):
    TYPE = dns.rdatatype.A
    
    def __init__(self: "RiskyRecord", record, domain: Domain) -> None:
        self.record_type    = "A"
        super().__init__(record.address, domain)

    
    def get_info(self: "RiskyRecordA") -> dict :
        """"Search for an IP in the IP ranges dictionary. If found, return IP range info."""
        if self.points_to:
            ip = ipaddress.IPv4Address(self.points_to)
            for subnet, info in self.domain.service_ranges.items():
                if ip in subnet:
                    return info

        return


    def determine_risk(self: "RiskyRecordA") -> str:
        self.aws_info = self.get_info()

        if self.aws_info:
            if self.aws_info['service'] == "S3" or self.aws_info['service'] == "CLOUDFRONT":
                headers = {"Host" : f"{self.domain.domain_name}"} #since we are using an IP address, also add a host header
                resource_exists = requests.get(f"http://{self.points_to}", headers=headers)

                if resource_exists.status_code == 404:
                    self.risk = "RISKY"
                    self.info = f"You do not own this {self.aws_info['service']} resource and it is available for anyone to register."

            elif self.domain.user_owned_ips and self.points_to in self.domain.user_owned_ips:
                self.risk = "RISKY"
                self.info = "You own the currently own this IP. Consider using a CNAME."
            else:
                if self.domain.user_owned_ips:
                    self.risk  = "RISKY"
                    self.info  = "IP is NOT owned but an A record points to it for a service that could reassigned."
                
                else:
                    self.risk  = "WARN"
                    self.info  = "An A record points to an AWS IP. Unable to determine if IP is owned without a list of owned IPs."

            return self.risk
  



class RiskyRecordCNAME(RiskyRecord):
    TYPE = dns.rdatatype.CNAME

    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html#VirtualHostingLimitations
    CNAME_BUCKET_TYPES = {
        "path_style"             : re.compile(r's3\.([a-zA-Z0-9._-]+)\.amazonaws\.com/[a-zA-Z0-9._-]+/.*'),
        "virtual_hosted_style"   : re.compile(r'([a-zA-Z0-9._-]+)\.s3\.[a-z0-9-]+\.amazonaws\.com.*'),
        "legacy_s3-region"       : re.compile(r'([a-zA-Z0-9._-]+)\.s3-[a-z0-9-]+\.amazonaws\.com.*'),
        "legacy_global_endpoint" : re.compile(r'([a-zA-Z0-9._-]+)\.s3\.amazonaws\.com.*')
    }

    def __init__(self: "RiskyRecord", record, domain: Domain) -> None:
        self.record_type = "CNAME"
        
        super().__init__(record.target, domain)
        self.points_to = self.points_to[:-1] #remove extra "."
    

    def get_info(self: "RiskyRecordCNAME") -> dict:
        """
        Use Regex to determine if a CNAME is pointing to a S3 bucket. If yes, return the style of URL syntax. Also checks region of the bucket.
        """
        if self.aws_info:
            return self.aws_info["bucket_type"]

        for key, pattern in self.CNAME_BUCKET_TYPES.items():
            if pattern.match(self.points_to):
                self.aws_info["bucket_type"]  = key
                self.aws_info["bucket_name"]  = pattern.match(self.points_to).groups(1)
                self.aws_info["service"]      = "S3"
                self.aws_info["resource"]     = "bucket"
                return self.aws_info

        return


    def determine_risk(self: "RiskyRecordCNAME") -> str:
        self.aws_info = self.get_info()
        resource_exists = requests.get(f"http://{self.points_to}")
        if self.aws_info and resource_exists.status_code == 404:
            self.risk = "RISKY"
            self.info = "You do not own this bucket and it is available for anyone to register."

        elif self.aws_info:
            if self.domain.user_owned_buckets and self.points_to in self.domain.user_owned_buckets:
                self.risk = "WARN"
                self.info = f"{self.aws_info["bucket_type"]} syntax bucket URL detected and you own the currently own this bucket. Make sure to delete this record before the bucket if you no longer need it"
                
            else:
                if self.domain.user_owned_buckets:
                    self.risk  = "RISKY"
                    self.info  = f"{self.aws_info["bucket_type"]} syntax bucket URL detected but is NOT owned and a CNAME record points to it."
                       
                else:
                    self.risk  = "WARN"
                    self.info  = f"{self.aws_info["bucket_type"]} syntax bucket URL detected but unable to determine if bucket is owned without a list of owned buckets."
                    
        return self.risk
    
class RiskyRecordEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, RiskyRecord):
            return {"domain": obj.domain.domain_name,"record_type": obj.record_type, "points_to" : obj.points_to, "metadata": obj.aws_info,  "risk": obj.risk, "info": obj.info }
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)
    


async def main():   
    start_time = time()
    
    console.print("Retrieving current ip-ranges.json from AWS", style="cyan")
    async with aiohttp.ClientSession() as session:
        async with session.get("https://ip-ranges.amazonaws.com/ip-ranges.json") as response:
            ip_ranges = await response.json()

    console.print(f"Filtering by {args.services} Service IP Range(s)", style="cyan")
    services       = args.services.split(",")
    service_ranges = {}
    for service in services:
        service_ranges.update(filter_ranges_by_service(ip_ranges, service))

  

    console.print(f"Reading in domains from {args.file}", style="cyan")
    domain_names = read_list_file(args.file)

    if args.owned_ips:
        console.print(f"Reading user-owned IP addresses from {args.owned_ips}", style="cyan")
        user_ips = read_list_file(args.owned_ips)


    if args.owned_buckets:
        console.print(f"Reading user-owned buckets from {args.owned_buckets}", style="cyan")
        user_buckets = read_list_file(args.owned_buckets)

    if args.dns_server:
        console.print(f"Using {args.dns_server} as the name server", style="cyan")
        user_dns = args.dns_server

    domains = []
    tasks = []
    for domain_name in domain_names:
        domain = Domain(domain_name,
                        service_ranges,
                        dns_server=user_dns if args.dns_server else "8.8.8.8",
                        user_owned_ips=user_ips if args.owned_ips else None,
                        user_owned_buckets=user_buckets if args.owned_buckets else None
                    )
        domains.append(domain)
        task = asyncio.create_task(domain.process_domain())
        tasks.append(task)

    with Progress(console=console) as progress:
        task = progress.add_task(f"\nChecking {len(domain_names)} domains...", total=len(domain_names))
        
        sem = asyncio.Semaphore(1)
        for completed_task in asyncio.as_completed(tasks):
            try:
                async with sem:
                    await completed_task
            #except Exception as exc:
                #console.print(f"[red]Exception for a domain: {exc}[/red]")
            finally:
                progress.update(task, advance=1)
                        

    if args.print_summary:
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Record", style="dim")
        table.add_column("Record Type", style="dim")
        table.add_column("Points to")
        table.add_column("AWS info")
        table.add_column("Risk Rating")
        table.add_column("Info")
        
        for domain in domains:
            for record in domain.risky_records:
                table.add_row(record.domain.domain_name,
                            record.record_type, 
                            record.points_to,
                            repr(record.aws_info),
                            record.risk,
                            record.info
                            )
        
        console.print(table)
        console.print(f"\nSummary: found {table.row_count} risky records.", style="magenta")
        console.print(f"The following domains had risky records.", style="magenta")

    if args.output:
        console.print("\nJSON for all risky records. Check your AWS account(s) to confirm you possess the IPv4 address.", style="magenta")
        console.print("If you release an EC2 IPv4 address, always be sure to delete or update your DNS records\n", style="magenta")
        
        write_json_file(args.output, domains)
        console.print(f"Risky records saved to {args.output}", style="cyan")
    
    end_time = time()
    elapsed_time = end_time - start_time
    console.print(f"Execution time: {elapsed_time:.2f} seconds", style="cyan")

if __name__ == "__main__":
    asyncio.run(main())
