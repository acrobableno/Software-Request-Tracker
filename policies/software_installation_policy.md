# Software Installation Policy (SAMPLE)

> SAMPLE DOCUMENT for demonstration only. Replace with your organisation's approved policy.

## 1. Purpose
This policy sets the rules for requesting, approving and installing software on organisation-managed
devices, so that only licensed, supported and secure software is used.

## 2. Scope
Applies to all staff, contractors and vendors using organisation-managed laptops, desktops and servers,
and to cloud (SaaS) services used to process organisation data.

## 3. Default rule: not allowed unless approved
3.0 **All software is NOT allowed by default.** Software may be installed only if:
  (a) it is listed under "Pre-approved" in the Approved Software Catalogue, or
  (b) an admin has approved a software request for it (status "Approved" or "Approved with Conditions").
Software that is not mentioned in any policy is NOT allowed. An approval applies only to the request,
version and platform it was given for; other staff must submit their own request.

## 3A. Request and approval
3.1 All software not listed as Pre-approved in the Approved Software Catalogue must be requested through the Software Request app.
3.2 Each request must state the business justification, the version and the platform.
3.3 Requests are approved by the IT Security team. Requests for software in the Restricted category also
require written approval from the CISO.
3.4 Pre-approved software in the Approved Software Catalogue may be installed without a request,
provided the latest supported version is installed.

## 4. Security requirements
4.1 Only the latest vendor-supported version may be installed. Versions that are end-of-life (no longer
receiving security updates) must not be approved.
4.2 Software with an unpatched vulnerability listed in the CISA Known Exploited Vulnerabilities (KEV)
catalog must be rejected until a fixed version is available and requested.
4.3 Software with unpatched critical vulnerabilities (CVSS 9.0 or above) must be rejected, or approved
only on the fixed version.
4.4 Software with unpatched high vulnerabilities (CVSS 7.0 to 8.9) may be approved with conditions,
for example installing the fixed version or restricting use to non-sensitive data.
4.5 Software must be downloaded only from the vendor's official website, an official package manager
(Microsoft Store, winget, Chocolatey managed by IT, Homebrew managed by IT) or the IT software portal.

## 5. Prohibited categories
The following must not be approved:
- Peer-to-peer (P2P) file sharing and torrent clients.
- Cryptocurrency miners.
- Password crackers, network scanners and hacking tools, unless for an approved security team role.
- Unlicensed, cracked or "keygen" software.
- Software that disables or bypasses endpoint protection, VPN or web filtering.

## 6. Restricted categories (CISO approval required)
- Remote access and remote control tools (for example TeamViewer, AnyDesk).
- Personal cloud storage and file-sync clients used with organisation data.
- Browser extensions that can read or change data on all websites.
- AI tools or SaaS services that will process Confidential or higher classified data.

## 7. Licensing
7.1 Commercial software must have a valid organisation licence before installation.
7.2 Freeware must allow commercial or government use under its licence terms.
7.3 Open-source software is allowed when its licence is permissive (MIT, Apache 2.0, BSD) or LGPL/GPL
for unmodified desktop use. Embedding GPL code in products requires Legal review.

## 8. Data protection
Cloud (SaaS) software that stores or processes organisation data must have a data-hosting location and
security assessment approved by IT Security before use with Confidential data.

## 9. Review
Approved software is reviewed yearly. Software that reaches end-of-life must be upgraded or removed
within 30 days.
