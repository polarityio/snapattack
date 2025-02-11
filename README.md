# Polarity SnapAttack Integration
SnapAttack is a cybersecurity company that provides a platform for proactive threat hunting, detection engineering, and operationalized threat intelligence, enabling organizations to detect and defend against cyber threats before they occur. The platform combines threat intelligence, adversary emulation, detection analytics, and collaboration tools to help identify vulnerabilities, strengthen systems against potential attacks, and optimize existing security tools and teams.

## Integration Overview

The Polarity - SnapAttack integration enables analysts to search for Threat Vulnerabilities (CVE), and either tagged Threat Actors or tagged Mitre ATT&CK techniques giving users a quick overview of a threat actor and context around vulnerabilities.

| ![](images/cve.png) | ![](images/threat-actor.png) |
|---------------------|------------------------------------------|
| *CVE Example*       | *Threat Actor Example*                   |     

## SnapAttack Integration Options

### API Key

A valid SnapAttack API key is required for the integration to function. To obtain an API Key, navigate to Settings -> API Keys and create one. 

### Threat Actor or Mitre Attack Technique searching

The Polarity - SnapAttack integration enables analysts to specify which datasets to query for the integration. Analysts can choose to search Threat Actors (default) or Mitre Attack Techniques. The integration will search vulnerabilities by default. 

**HINT** Threat actor and MITRE ATT&CK lookups require case-insensitive exact matches against specific tagged attacks or actors in SnapAttack.  For example, to lookup the technique `T1036` requires searching on the tagged string `T1036: Masquerading`. 

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/