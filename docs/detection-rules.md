# Detection rules for AiTM token theft and persistence

Microsoft Sentinel / Advanced Hunting (KQL). Validate table names and tune thresholds for your
tenant before enabling. These detect the *replay* and *persistence* stages — the part a link
scanner cannot see.

## A. New device or MFA method right after a risky sign-in
The persistence move from your incident: a device registration or new auth method minutes
after an unfamiliar sign-in.

```kql
let window = 30m;
let risky =
    AADSignInEventsBeta
    | where RiskLevelDuringSignIn in ("high", "medium")
        or RiskState == "atRisk"
    | project RiskTime = TimeGenerated, AccountUpn = UserPrincipalName, IPAddress;
AuditLogs
| where OperationName has_any ("Add registered device", "Register device",
        "Add security info", "User registered security info", "Add a new MFA method")
| extend AccountUpn = tostring(TargetResources[0].userPrincipalName)
| join kind=inner risky on AccountUpn
| where TimeGenerated between (RiskTime .. (RiskTime + window))
| project TimeGenerated, AccountUpn, OperationName, RiskTime, IPAddress
```

## B. Session replayed from a hosting provider shortly after an interactive sign-in
AiTM replay often comes from a cloud/hosting ASN while the user signed in from a normal
network minutes earlier.

```kql
let hosting = dynamic(["AMAZON","MICROSOFT-CORP-MSN-AS-BLOCK","DIGITALOCEAN",
    "GOOGLE-CLOUD","OVH","HETZNER","CHOOPA","Linode","M247","DataCamp"]);
SigninLogs
| where ResultType == 0
| extend ASN = tostring(parse_json(AutonomousSystemNumber))
| summarize byInteractive = countif(IsInteractive == true),
            byNonInteractive = countif(IsInteractive == false),
            asns = make_set(AutonomousSystemOrganization, 10)
          by UserPrincipalName, bin(TimeGenerated, 1h)
| where byInteractive > 0 and byNonInteractive > 0
| mv-expand asn = asns to typeof(string)
| where asn has_any (hosting)
```

## C. Token / cookie reused from a second IP (impossible travel on one session)
```kql
SigninLogs
| where ResultType == 0
| summarize ips = make_set(IPAddress, 25), locs = make_set(Location, 25)
          by UserPrincipalName, SessionId = tostring(parse_json(AuthenticationProcessingDetails))
| where array_length(ips) > 1
```

## D. Beacon alert enrichment
When the luretrace login-page beacon reports `verdict=proxied`, the `origin_host` is the live
phishing domain. Pipe it to a watchlist and join sign-ins against it, and push it to your
web gateway's custom URL blocklist via the `luretrace` IOC export.

## Automated response (Logic App / SOAR)
On a confirmed hit from A, B, or the beacon:
1. Revoke the user's sessions (`Revoke-MgUserSignInSession`).
2. Disable the account or raise user risk to force remediation.
3. Remove any device or MFA method registered inside the alert window.
4. Hunt for inbox rules and new OAuth grants created in the same window.
5. Block the phishing domain at the web gateway and the mail gateway.
