# Deploying luretrace in an enterprise environment

This is a reference architecture for running luretrace as a production SOC service. It assumes
Microsoft 365 for mail and Azure for hosting; the shape maps cleanly onto AWS or GCP. luretrace
opens live phishing pages on purpose, so isolation is the first requirement, not an afterthought.

> Status: **beta** (`0.1.0b1`), not production-validated. Treat the first rollout as a lab pilot,
> not a production deployment. The Microsoft Graph and Mimecast integrations are written to vendor
> docs and must be validated against a test tenant first.

## 1. Network isolation (non-negotiable)

The detonation workers execute hostile content. They must not be able to reach anything
corporate.

- Run them in a dedicated VNet, ideally in their own Azure subscription, with **no peering** to
  corporate networks.
- Egress through a NAT gateway with its own public IPs. Prefer egress IPs that resemble normal
  user traffic (route through your Netskope egress or a residential-style proxy); datacenter IPs
  are fingerprinted by kits, which then serve a decoy.
- At the subnet NSG, in addition to the app's built-in guard:
  - Deny outbound to RFC1918 (10/8, 172.16/12, 192.168/16) and link-local 169.254.0.0/16
    (blocks the cloud metadata endpoint 169.254.169.254).
  - Allow outbound 80/443 to the internet only.
  - Deny all inbound except your management path (e.g. Bastion / just-in-time SSH).
- Defence in depth: the worker's `netguard` refuses non-public targets at the application layer,
  and the config `proxy` forces browser traffic through your controlled egress. The NSG is the
  hard boundary; the app guard is the backstop.

## 2. Hosting and sizing

- **Pilot:** 1-2 hardened VMs running the shipped `docker-compose.yml` (scanner, plus the
  optional pcap sidecar). Chromium uses roughly 1 GB RAM per concurrent browser; size for your
  peak concurrency plus headroom.
- **Keep the console off the detonation path.** Set `LURETRACE_INBOX` on the console and
  `inbox_dir` on the worker to the same shared directory: console submissions become job files
  the isolated worker drains (`luretrace watch` drains it every poll; `luretrace drain` runs it
  once). Jobs are claimed by atomic rename, so several workers can share one inbox.
- **Scale:** move to AKS or Azure Container Apps with a worker pool. At that point replace the
  JSON-backed rescan queue (`rescan.py`) and the file inbox with a durable queue — Azure Storage
  Queue, Service Bus, or Redis — so work survives restarts and spreads across workers.
- Run the container as shipped: non-root, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, tmpfs for scratch. Patch the Playwright base image on a schedule; a
  browser CVE in the detonation path is a real SSRF/RCE risk.

## 3. Mail feed

Scope the input narrowly first, widen later.

- **Start with the user report-phish button.** Route reported mail to a dedicated mailbox
  (e.g. `linkscan@yourcompany.com`). Highest signal, lowest volume, best pilot input.
- **Later, optionally** BCC inbound external mail containing URLs to the same mailbox via a
  transport rule, or use journaling. This is high volume — add worker capacity before enabling.
- Access the mailbox with **Microsoft Graph, application permissions**, `Mail.ReadWrite`, scoped
  to that one mailbox with an application access policy. Prefer certificate credentials over a
  client secret.

## 4. Integration with the SOC stack

- **Incident creation:** verdict webhook → ServiceNow Security Incident (or Microsoft Sentinel
  via a Logic App). Attach the verdict, the chain, and the screenshot path. Set
  `webhook_secret` and verify `X-Luretrace-Signature` (`sha256=` HMAC of the raw body) on the
  receiver; failed deliveries are retried with backoff (`webhook_retries`).
- **Blocking:** `blocklist_path` appends each malicious verdict's domains to a one-per-line file
  (or run `luretrace blocklist out.txt` over the scans on disk); push it to a Netskope custom URL
  category and your mail gateway's blocked-URL list. Shared platforms (SharePoint, Dropbox,
  `pages.dev`, a brand's own domains) are never blocked whole: only the exact host that served
  the credential form or download is listed, and never the file-share lure itself.
- **Ingest:** `luretrace ingest` pulls links from the configured connector (`ingest: {kind:
  mimecast|datalake, ...}`) and prints where the gateway passed a link luretrace failed.
- **Login-page beacon:** run `luretrace beacon` on a reachable host, reference it from your Entra
  sign-in branding, and forward `verdict=proxied` hits to the same incident queue. The
  `origin_host` is the live phishing domain — auto-add it to the blocklists.
- **Detections:** load `docs/detection-rules.md` into Sentinel to catch the replay and
  persistence stages the scanner cannot see.

## 5. Secrets and identity

- Store Graph, Mimecast, and webhook credentials in Azure Key Vault.
- The container pulls them at runtime via its managed identity. Nothing sensitive in
  `config.yaml` on disk; mount only non-secret config.
- Least privilege on every token. Review the Graph app's permissions quarterly.

## 6. Data handling and governance

- **Artifacts are hazardous.** Saved HTML, screenshots, and downloads are live malicious content
  and may contain PII lifted from the lure. Store them in a restricted location with short
  retention and access logging. Expect this to fall inside your compliance scope.
- **Honeytoken stays disabled in production** until legal and leadership approve active
  deception. When approved, seed the canary as a disabled, monitored identity and keep the
  malicious-only gate.
- **Allowlist** your phishing-simulation vendor (KnowBe4, etc.) and one-click action /
  unsubscribe domains, or detonation will trigger them and skew simulation metrics.
- **Detonation is observable.** Visiting a link can confirm the mailbox is live and tip the
  attacker. Egress from addresses not tied to your organisation.
- Put the service under change management with a named owner and an on-call runbook.

## 7. Staged rollout

1. Report-phish mailbox -> one worker VM in the isolated subnet -> **alert-only**. No
   auto-block, no honeytoken.
2. Tune thresholds (`malicious_threshold`, `suspicious_threshold`) and the allowlist against a
   few weeks of real reports. Measure it: `luretrace eval labels.csv --out eval.json` reports
   precision, recall and false-positive rate over a labelled set (fresh phishing-feed links plus a
   benign corpus). Re-run it on every release and every tuning change.
3. Enable automatic blocklist push to Netskope and the mail gateway.
4. Add the login-page beacon and the Sentinel detections.
5. Only then weigh active response (Graph message purge, honeytoken) with sign-off.

## 8. What to harden before production

- Durable queue in place of the JSON rescan file and the file inbox.
- Validate the Graph source and `graph_purge` (`purge_on_malicious`), and the Mimecast decoder,
  against a test tenant. The purge moves a message to Deleted Items (recoverable) and only when
  its Message-ID matches exactly one message in that mailbox.
- Put the console and gate behind your SSO; the console adds CSRF protection and strict security
  headers but has no login of its own.
- Central logging of every verdict and action for audit (actions are recorded in each
  `report.json` and the webhook payload).
- Secrets in Key Vault, not files.
- Automated patching of the Playwright/Chromium base image.

---

## Appendix: isolated network + worker VM (Terraform sketch)

Illustrative, not production-ready. No peering, locked-down NSG, dedicated egress. Review and
parameterise before use.

```hcl
resource "azurerm_resource_group" "deton" {
  name     = "rg-luretrace-detonation"
  location = "eastus2"
}

resource "azurerm_virtual_network" "deton" {
  name                = "vnet-luretrace"
  address_space       = ["10.80.0.0/24"]
  location            = azurerm_resource_group.deton.location
  resource_group_name = azurerm_resource_group.deton.name
  # Deliberately NOT peered to any corporate VNet.
}

resource "azurerm_subnet" "workers" {
  name                 = "snet-workers"
  resource_group_name  = azurerm_resource_group.deton.name
  virtual_network_name = azurerm_virtual_network.deton.name
  address_prefixes     = ["10.80.0.0/26"]
}

# Dedicated egress IP so all detonation traffic leaves from one known address.
resource "azurerm_public_ip" "nat" {
  name                = "pip-luretrace-nat"
  location            = azurerm_resource_group.deton.location
  resource_group_name = azurerm_resource_group.deton.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_nat_gateway" "egress" {
  name                = "nat-luretrace"
  location            = azurerm_resource_group.deton.location
  resource_group_name = azurerm_resource_group.deton.name
  sku_name            = "Standard"
}

resource "azurerm_nat_gateway_public_ip_association" "egress" {
  nat_gateway_id       = azurerm_nat_gateway.egress.id
  public_ip_address_id = azurerm_public_ip.nat.id
}

resource "azurerm_subnet_nat_gateway_association" "workers" {
  subnet_id      = azurerm_subnet.workers.id
  nat_gateway_id = azurerm_nat_gateway.egress.id
}

resource "azurerm_network_security_group" "workers" {
  name                = "nsg-luretrace-workers"
  location            = azurerm_resource_group.deton.location
  resource_group_name = azurerm_resource_group.deton.name

  # Block the cloud metadata endpoint and all private ranges outbound.
  security_rule {
    name                       = "deny-metadata"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "169.254.0.0/16"
  }
  security_rule {
    name                       = "deny-rfc1918"
    priority                   = 110
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefixes = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
  security_rule {
    name                       = "allow-web-out"
    priority                   = 200
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443"]
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
  }
  security_rule {
    name                       = "deny-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "workers" {
  subnet_id                 = azurerm_subnet.workers.id
  network_security_group_id = azurerm_network_security_group.workers.id
}
```

Management access (SSH/RDP) should be added through Azure Bastion with just-in-time access, not
a public inbound rule.
