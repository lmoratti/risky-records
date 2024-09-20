# Risky Records

This script checks DNS A and CNAME records for a list of domains against AWS IP ranges, helping identify potentially risky or unowned resources in your or your client's cloud infrastructure. 

This tool was designed with **blackbox or greybox pentesting** in mind. *There are better options for whitebox or those looking to continously monitor their domains.*

Risky Records allows you to query domains and verify if any of their DNS records point to AWS services like EC2 or S3, particularly when those resources may not be owned by your organization.

Without a list of IPs or buckets that are confirmed to be owned by you or your client it will simply point out which service is in use. If you have those lists, it will show you which records are risky. It is a best effort risk determination based on the information you are able to supply.

## Features

- **Check Domains**: Retrieve DNS records for a list of domains and evaluate them against AWS IP ranges.
- **Filter AWS Services**: Filter by specific AWS services (e.g., EC2, S3).
- **User-Owned Resource Matching**: Verify DNS records against user-provided lists of owned IP addresses and S3 buckets.
- **Risk Reporting**: Identify potentially risky DNS records (e.g., pointing to resources that are available for public registration).
- **Output Options**: Save results in JSON format or print a detailed summary to the console.

## Requirements

- Python 3.11
- Install dependencies via pip:

  ```bash
  pip install -r requirements.txt
  ```

## Usage

Run the script from the command line:

```bash
python risky_records.py --file <domains.txt> --services EC2,S3 --owned-ips <owned_ips.txt> --owned-buckets <owned_buckets.txt> --output <output.json> --print-summary
```

### Arguments

- `--file`: Path to the file containing domain names (required).
- `--services`: AWS service names to filter IP ranges by. Default is `EC2,S3`.
- `--dns-server`: DNS server to query for A records. Default is `8.8.8.8`.
- `--owned-ips`: Path to the file containing user-owned IP addresses (optional).
- `--owned-buckets`: Path to the file containing user-owned S3 buckets (optional).
- `--output`: Filename to store JSON output of all risky records (optional).
- `--print-summary`: Print a summary of risky records (optional).

### Example

To check domains against EC2 and S3 IP ranges and print a summary of risky records:

```bash
python risky_records.py  --file domains.txt --services EC2,S3 --print-summary
```

To store the output in JSON format:

```bash
python risky_records.py --file domains.txt --services EC2,S3 --output risky_records.json
```

## Output

If `--print-summary` is used, a table summarizing the risky records will be printed. Each row will include:

- **Record**: Domain name.
- **Record Type**: The type of DNS record (A or CNAME).
- **Points To**: The IP or hostname the record points to.
- **AWS Info**: Information on the AWS service the IP/host belongs to.
- **Risk Rating**: The level of risk (`RISKY`, `WARN`).
- **Info**: Additional details on why the record is considered risky.

If the `--output` argument is used, the results will be saved to a JSON file containing details of risky records.

### Example JSON Output:

```json
[
  {
    "domain": "example.com",
    "record_type": "A",
    "points_to": "54.239.26.128",
    "metadata": {
      "service": "EC2",
      "region": "us-east-1"
    },
    "risk": "WARN",
    "info": "An A record points to an AWS IP. Unable to determine if IP is owned without a list of owned IPs."
  }
]
```

## Comparison to Other Tools

While other tools (like [Subfinder](https://github.com/projectdiscovery/subfinder) or [Amass](https://github.com/OWASP/Amass)) are widely used for DNS enumeration and asset discovery, this script focuses specifically on identifying risky DNS records related to AWS infrastructure. It includes:

- **AWS-Specific Filtering**: This tool lets you filter by AWS services such as EC2,S3, or CLOUDFRONT which is more niche compared to broader subdomain enumeration tools.
- **Custom Risk Assessment**: It incorporates checks for user-owned IPs and buckets, providing best-effort risk analysis.

### Differences:
- **Subfinder** and **Amass**: Focus on broad asset discovery and subdomain enumeration without AWS-specific risk assessments. 
- **Risky Records**: Provides AWS-centric filtering and evaluation, with specific focus on DNS misconfigurations and resource ownership. The more information risky records has about IPs or Buckets you or your client owns the more detailed information it can provide. It is best suited for greybox or blackbox enumeration for pentesters. There are better options for whitebox monitoring of domains such as [Domain Protect (OWASP)](https://github.com/domain-protect/domain-protect)


