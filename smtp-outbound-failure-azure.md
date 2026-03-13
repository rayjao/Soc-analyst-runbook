# SMTP Outbound Failure - Azure Subscription Port 25 Block

## Incident Summary
Server unable to send outbound email through Proofpoint. 
All connection attempts timing out on port 25.

## Environment
- Platform: Microsoft Azure (BackEndDMZ)
- Mail Relay: Proofpoint Essentials
- Subnet: VLAN-170-DMZ (10.x.x.0/24)
- Affected Server: [Internal Azure VM IP]
- Public Egress IP: [Azure Public IP]

## Symptoms
- DNS resolution working correctly
- Port 25 connections timing out to all Proofpoint MX hosts
- No SMTP banner received — Proofpoint never sees the connection

## Troubleshooting Steps

### 1. Server Level
- Verified DNS resolution working
- Confirmed no local firewall blocking port 25
- Confirmed TCP timeout — not an application rejection

### 2. Azure Level
- Confirmed no Azure Firewall deployed
- NSG outbound rules verified — port 25 allowed
- IP flow verify returned "Allowed" on port 25
- Public IP (1**.**0.**.*0) confirmed attached to NIC

### 3. Network Path
- Tracert showed traffic dying after first hop
- Route table confirmed VPN hairpin through on-prem
- Meraki firewall Rule 8 identified as potential block
- On-prem ruled out after further testing

### 4. Confirmation Test
- Port 25 to Proofpoint — FAILED
- Port 25 to Gmail — FAILED
- Port 587 to Gmail — SUCCEEDED
- Port 587 to Proofpoint — SUCCEEDED

## Root Cause
Azure blocks outbound port 25 at the subscription/fabric level. 
This block operates below the NSG layer — NSG allow rules 
cannot override it. IP flow verify and NSG diagnostics show 
"Allowed" because they only evaluate NSG rules, not 
platform-level blocks.

## Resolution
Reconfigured mail application on BackEndDMZ to relay through 
Proofpoint on port 587 (STARTTLS) instead of port 25.

## Key Takeaways
- Azure blocks port 25 outbound by default on all subscriptions
- NSG rules cannot override Azure fabric-level port blocks
- IP flow verify does NOT detect platform-level blocks
- Port 587 is the correct port for SMTP relay in Azure

## Commands Used
# Check egress IP
Invoke-RestMethod http://ipinfo.io/json

# Test SMTP connectivity
Test-NetConnection -ComputerName <mail-relay-host> -Port 25 -InformationLevel Detailed
Test-NetConnection -ComputerName <mail-relay-host> -Port 587 -InformationLevel Detailed

# Trace network path
tracert -d 67.231.154.162
