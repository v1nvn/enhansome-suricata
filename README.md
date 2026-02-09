# Awesome Suricata [![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re) with stars

[<img src="https://suricata.io/wp-content/uploads/2022/01/Logo-SuricataFinal-1-translucent.png" align="right" width="120">](https://suricata.io)

> Curated list of awesome things related to Suricata.

[Suricata](https://suricata.io/features) is a free intrusion detection/prevention system (IDS/IPS) and network security monitoring engine.

## Contents

* [Input Tools](#input-tools)
* [Output Tools](#output-tools)
* [Operations, Monitoring and Troubleshooting](#operations-monitoring-and-troubleshooting)
* [Programming Libraries and Toolkits](#programming-libraries-and-toolkits)
* [Dashboards and Templates](#dashboards-and-templates)
* [Development Tools](#development-tools)
* [Documentation and Guides](#documentation-and-guides)
* [Analysis Tools](#analysis-tools)
* [Rule Sets](#rule-sets)
* [Rule/Security Content Management and Handling](#rulesecurity-content-management-and-handling)
* [Plugins and Extensions](#plugins-and-extensions)
* [Systems Using Suricata](#systems-using-suricata)
* [Training](#training)
* [Simulation and Testing](#simulation-and-testing)
* [Data Sets](#data-sets)
* [Misc](#misc)

## Input Tools

* [PacketStreamer](https://github.com/deepfence/PacketStreamer) ⭐ 1,927 | 🐛 22 | 🌐 Go | 📅 2024-07-01 - Distributed tcpdump for cloud native environments.

## Output Tools

* [Suricata-Logstash-Templates](https://github.com/pevma/Suricata-Logstash-Templates) ⭐ 81 | 🐛 3 | 📅 2016-03-12 - Templates for Kibana/Logstash to use with Suricata IDPS.
* [FEVER](https://github.com/DCSO/fever) ⭐ 57 | 🐛 2 | 🌐 Go | 📅 2025-11-20 - Fast, extensible, versatile event router for Suricata's EVE-JSON format.
* [Meer](https://github.com/quadrantsec/meer) ⭐ 30 | 🐛 8 | 🌐 C | 📅 2023-06-21 - A "spooler" for Suricata / Sagan.
* [suricata-kafka-output](https://github.com/Center-Sun/suricata-kafka-output) ⭐ 15 | 🐛 2 | 🌐 Rust | 📅 2021-11-25 - Suricata Eve Kafka Output Plugin for Suricata 6.
* [suricata-redis-output](https://github.com/jasonish/suricata-redis-output) ⭐ 8 | 🐛 1 | 🌐 Rust | 📅 2026-02-05 - Suricata Eve Redis Output Plugin for Suricata 7.
* [Lilith](https://github.com/VVelox/Lilith) ⭐ 1 | 🐛 0 | 📅 2022-11-25 - Reads EVE files into SQL as well as search stored data.

## Operations, Monitoring and Troubleshooting

* [InfluxDB Suricata Input Plugin](https://github.com/influxdata/telegraf/tree/master/plugins/inputs/suricata) ⭐ 16,685 | 🐛 441 | 🌐 Go | 📅 2026-02-06 - Input Plugin for Telegraf to collect and forward Suricata `stats` logs (included out of the box in recent Telegraf releases).
* [docker-suricata](https://github.com/jasonish/docker-suricata) ⭐ 313 | 🐛 6 | 🌐 Shell | 📅 2026-02-07 - Suricata Docker image.
* [suri-stats](https://github.com/regit/suri-stats) ⭐ 29 | 🐛 0 | 🌐 Python | 📅 2015-10-14 - A tool to work on suricata `stats.log` file.
* [suricata\_exporter](https://github.com/corelight/suricata_exporter) ⭐ 27 | 🐛 2 | 🌐 Go | 📅 2025-07-27 - Simple Prometheus exporter written in Go exporting stats metrics scraped from Suricata socket.
* [slinkwatch](https://github.com/DCSO/slinkwatch) ⭐ 11 | 🐛 7 | 🌐 Go | 📅 2019-12-10 - Automatic enumeration and maintenance of Suricata monitoring interfaces.
* [Terraform Module for Suricata](https://github.com/onetwopunch/terraform-google-suricata) ⭐ 10 | 🐛 0 | 🌐 HCL | 📅 2022-08-02 - Terraform module to setup Google Cloud packet mirroring and send packets to Suricata.
* [MassDeploySuricata](https://github.com/pevma/MassDeploySuricata) ⭐ 9 | 🐛 0 | 🌐 Shell | 📅 2014-12-07 - Mass deploy and update Suricata IDPS using Ansible IT automation platform.
* [Mauerspecht](https://github.com/DCSO/mauerspecht) ⭐ 3 | 🐛 0 | 🌐 Go | 📅 2025-03-14 - Simple Probing Tool for Corporate Walled Garden Networks.
* [Suricata-Monitoring](https://github.com/VVelox/Suricata-Monitoring) ⭐ 2 | 🐛 0 | 🌐 Perl | 📅 2024-06-04 - LibreNMS JSON / Nagios monitor for Suricata stats.
* [ansible-suricata](https://github.com/GitMirar/ansible-suricata) ⭐ 1 | 🐛 0 | 📅 2018-06-30 - Suricata Ansible role (slightly outdated).

## Programming Libraries and Toolkits

* [py-idstools](https://github.com/jasonish/py-idstools) ⚠️ Archived - Snort and Suricata Rule and Event Utilities in Python (Including a Rule Update Tool).
* [gonids](https://github.com/google/gonids) ⭐ 192 | 🐛 7 | 🌐 Go | 📅 2025-07-18 - Go library to parse intrusion detection rules for engines like Snort and Suricata.
* [suricataparser](https://github.com/m-chrome/py-suricataparser) ⭐ 33 | 🐛 2 | 🌐 Python | 📅 2024-03-13 - Pure python parser for Snort/Suricata rules.
* [surevego](https://github.com/rhaist/surevego) ⭐ 15 | 🐛 0 | 🌐 Go | 📅 2019-05-16 - Suricata EVE-JSON parser in Go.
* [go-suricata](https://github.com/ks2211/go-suricata) ⭐ 13 | 🐛 5 | 🌐 Go | 📅 2020-08-23 - Go Client for Suricata (Interacting via Socket).
* [rust-suricatax-rule-parser](https://github.com/jasonish/rust-suricatax-rule-parser) ⭐ 11 | 🐛 0 | 🌐 Rust | 📅 2025-11-26 - Experimental Suricata Rule Parser in Rust.

## Dashboards and Templates

* [KTS5](https://github.com/StamusNetworks/KTS5) ⭐ 43 | 🐛 4 | 🌐 Python | 📅 2018-05-30 - Kibana 5 Templates for Suricata IDPS Threat Hunting.
* [KTS7](https://github.com/StamusNetworks/KTS7) ⭐ 43 | 🐛 5 | 📅 2025-12-23 - Kibana 7 Templates for Suricata IDPS Threat Hunting.
* [KTS](https://github.com/StamusNetworks/KTS) ⭐ 33 | 🐛 3 | 🌐 Shell | 📅 2016-07-28 - Kibana 4 Templates for Suricata IDPS Threat Hunting.
* [KTS6](https://github.com/StamusNetworks/KTS6) ⭐ 24 | 🐛 5 | 🌐 Python | 📅 2019-03-05 - Kibana 6 Templates for Suricata IDPS Threat Hunting.

## Development Tools

* [Suricata Language Server](https://github.com/StamusNetworks/suricata-language-server) ⭐ 84 | 🐛 4 | 🌐 Python | 📅 2026-02-08 - An implementation of the Language Server Protocol for Suricata signatures. It adds syntax check, hints and auto-completion to your preferred editor once it is configured.
* [SublimeSuricata](https://github.com/ozuriexv/SublimeSuricata) ⭐ 35 | 🐛 1 | 📅 2023-12-09 - Basic Suricata syntax highlighter for Sublime Text.
* [suricata-highlight-vscode](https://github.com/dgenzer/suricata-highlight-vscode) ⭐ 12 | 🐛 0 | 📅 2022-02-26 - Suricata Rules Support for Visual Studio Code (syntax highlighting, etc).
* [suricata-ls-vscode](https://github.com/StamusNetworks/suricata-ls-vscode) ⭐ 3 | 🐛 0 | 🌐 TypeScript | 📅 2025-11-13 - Suricata IntelliSense Extension using the Suricata Language Server.
* [Suricata-Check](https://suricata-check.teuwen.net/readme.html) - A command-line utility to provide feedback on Suricata rules. It can detect issues such as covering syntax validity, interpretability, rule specificity, rule coverage, and efficiency.

## Documentation and Guides

* [SEPTun](https://github.com/pevma/SEPTun) ⭐ 213 | 🐛 2 | 🌐 Makefile | 📅 2018-03-15 - Suricata Extreme Performance Tuning guide.
* [SEPTun-Mark-II](https://github.com/pevma/SEPTun-Mark-II) ⭐ 121 | 🐛 2 | 🌐 Makefile | 📅 2018-04-17 - Suricata Extreme Performance Tuning guide - Mark II.
* [suricata-4-analysts](https://github.com/StamusNetworks/suricata-4-analysts) ⭐ 61 | 🐛 3 | 🌐 Python | 📅 2025-04-28 - The Security Analyst's Guide to Suricata.
* [Suricata Community Style Guide](https://github.com/sidallocation/suricata-style-guide) ⭐ 10 | 🐛 3 | 📅 2024-06-27 - A collaborative document to collect style guidelines from the community of rule writers.

## Analysis Tools

* [Malcolm](https://github.com/cisagov/Malcolm) ⭐ 2,334 | 🐛 152 | 🌐 Python | 📅 2026-01-30 - A powerful, easily deployable network traffic analysis tool suite for full packet capture artifacts (PCAP files), Zeek logs and Suricata alerts.
* [Evebox](https://github.com/jasonish/evebox) ⭐ 482 | 🐛 16 | 🌐 Rust | 📅 2026-01-22 - Web Based Event Viewer (GUI) for Suricata EVE Events in Elastic Search.
* [Suricata Analytics](https://github.com/StamusNetworks/suricata-analytics) ⭐ 38 | 🐛 0 | 🌐 Jupyter Notebook | 📅 2025-11-20 - Various resources that are useful when interacting with Suricata data.

## Rule Sets

* [Quantum Insert detection for Suricata](https://github.com/fox-it/quantuminsert/blob/master/detection/suricata/README.md) ⭐ 214 | 🐛 0 | 🌐 HTML | 📅 2019-01-02 - Suricata rules accompanying Fox-IT's QUANTUM 2015 blog/BroCon talk.
* [Hunting rules](https://github.com/travisbgreen/hunting-rules) ⭐ 184 | 🐛 1 | 📅 2026-02-07 - Suricata IDS alert rules for network anomaly detection from Travis Green.
* [opnsense-suricata-nmaps](https://github.com/aleksibovellan/opnsense-suricata-nmaps) ⭐ 82 | 🐛 1 | 📅 2025-11-10 - OPNSense's Suricata IDS/IPS Detection Rules Against NMAP Scans.
* [nids-rule-library](https://github.com/klingerko/nids-rule-library#readme) ⭐ 29 | 🐛 0 | 📅 2023-07-24 - Collection of various open-source and commercial rulesets.
* [Cluster25/detection](https://github.com/Cluster25/detection) ⭐ 14 | 🐛 0 | 🌐 YARA | 📅 2024-01-23 - Cluster25's detection rules.
* [Antiphishing](https://github.com/julioliraup/Antiphishing) ⭐ 6 | 🐛 3 | 🌐 Python | 📅 2025-03-13 - Suricata rules and datasets to detect phishing attacks.
* [QuadrantSec Suricata Rules](https://github.com/quadrantsec/suricata-rules) ⭐ 4 | 🐛 0 | 📅 2026-01-05 - Set of Suricata rules published by QuadrantSec.
* [Stamus Lateral Movement Detection Rules](https://www.stamus-networks.com/blog/new-open-ruleset-for-detecting-lateral-movement-with-suricata) - Suricata ruleset to detect lateral movement.
* Networkforensic.dk (NF) rules sets:
  * [NF IDS rules](https://networkforensic.dk/SNORT/NF-local.zip)
  * [NF SCADA IDS Rules](https://networkforensic.dk/SNORT/NF-SCADA.zip)
  * [NF Scanners IDS Rules](https://networkforensic.dk/SNORT/NF-Scanners.zip)
* [3CORESec NIDS - Lateral Movement](https://dtection.io/ruleset/3cs_lateral) - Suricata ruleset focusing on lateral movement techniques (paid).
* [3CORESec NIDS - Sinkholes](https://dtection.io/ruleset/3cs_sinkholes) - Suricata ruleset focused on a curated list of public malware sinkholes (free).
* [PAW Patrules](https://pawpatrules.fr) - Another free (CC BY-NC-SA) collection of rules for the Suricata engine.

## Rule/Security Content Management and Handling

* [Scirius](https://github.com/StamusNetworks/scirius) ⭐ 676 | 🐛 119 | 🌐 Python | 📅 2025-12-23 - Web application for Suricata ruleset management and threat hunting.
* [OTX-Suricata](https://github.com/AlienVault-OTX/OTX-Suricata) ⭐ 113 | 🐛 10 | 🌐 Python | 📅 2024-04-26 - Create rules and configuration for Suricata to alert on indicators from an OTX account.
* [Aristotle](https://github.com/secureworks/aristotle) ⭐ 38 | 🐛 0 | 🌐 Python | 📅 2024-11-02 - Simple Python program that allows for the filtering and modifying of Suricata and Snort rulesets based on interpreted key-value pairs present in the metadata keyword within each rule.
* [IOCmite](https://github.com/sebdraven/IOCmite) ⭐ 36 | 🐛 7 | 🌐 Python | 📅 2022-11-09 - Tool to create dataset for suricata with indicators of MISP instances and add sightings in MISP if an indicator of dataset generates an alert.
* [suricata-prettifier](https://github.com/theY4Kman/suricata-prettifier) ⭐ 13 | 🐛 0 | 🌐 Python | 📅 2019-11-30 - Command-line tool to format and syntax highlight Suricata rules.
* [surify-cli](https://github.com/dgenzer/surify-cli) ⭐ 3 | 🐛 2 | 🌐 JavaScript | 📅 2021-08-10 - Generate suricata-rules from collection of IOCs (JSON, CSV or flags) based on your suricata template.
* [luaevilbit](https://github.com/regit/luaevilbit) ⭐ 2 | 🐛 0 | 🌐 Lua | 📅 2012-11-22 - An Evil bit implementation in luajit for Suricata.
* [sidallocation.org](https://sidallocation.org/) - Sid Allocation working group, list of SID ranges.
* [Lawmaker](https://www.3coresec.com/solutions/lawmaker) - Suricata IDS rule and fleet management system.

## Plugins and Extensions

* [suricata-zabbix](https://github.com/catenacyber/suricata-zabbix) ⭐ 2 | 🐛 0 | 🌐 Rust | 📅 2025-08-14 - Zabbix application layer plugin for Suricata.

## Systems Using Suricata

* [SELKS](https://github.com/StamusNetworks/SELKS) ⭐ 1,590 | 🐛 216 | 🌐 Shell | 📅 2025-09-13 - A Suricata-based intrusion detection system/intrusion prevention system/network security monitoring distribution.
* [Amsterdam](https://github.com/StamusNetworks/Amsterdam) ⚠️ Archived - Docker based Suricata, Elasticsearch, Logstash, Kibana, Scirius aka SELKS.
* [Shovel](https://github.com/FCSC-FR/shovel) ⭐ 84 | 🐛 3 | 🌐 JavaScript | 📅 2026-02-08 - Web interface to explore Suricata EVE outputs, with a primary focus on network analysis in CTF competitions.
* [Artica](https://github.com/dtouzeau/artica-suricata) ⭐ 1 | 🐛 0 | 🌐 Go | 📅 2025-12-01 - Suricata IDS integration for the [Artica](https://artica.systems) gateway appliance.
* [pfSense](https://www.pfsense.org) - A free network firewall distribution, based on the FreeBSD operating system with a custom kernel and including third party free software packages for additional functionality.
* [OPNsense](https://opnsense.org) - An open source, easy-to-use and easy-to-build FreeBSD based firewall and routing platform.

## Training

* [CDMCS](https://github.com/ccdcoe/CDMCS/tree/master) ⭐ 108 | 🐛 0 | 🌐 Jupyter Notebook | 📅 2024-06-06 - Cyber Defence Monitoring Course: Rule-based Threat Detection.
* [Experimental Suricata Training Environment](https://github.com/jasonish/experimental-suricata-training) ⭐ 6 | 🐛 0 | 🌐 Shell | 📅 2024-03-08 - Suricata Training Environment based on Docker(-Compose).

## Simulation and Testing

* [Leonidas](https://github.com/WithSecureLabs/leonidas) ⭐ 602 | 🐛 9 | 🌐 Python | 📅 2024-11-28 - Automated Attack Simulation in the Cloud, complete with detection use cases.
* [Dalton](https://github.com/secureworks/dalton) ⭐ 512 | 🐛 23 | 🌐 Python | 📅 2026-01-09 - Suricata and Snort IDS rule and pcap testing system.
* [speeve](https://github.com/satta/speeve) ⭐ 8 | 🐛 0 | 🌐 Go | 📅 2025-12-05 - Fast, probabilistic EVE-JSON generator for testing and benchmarking of EVE-consuming applications.

## Data Sets

* [suricata-sample-data](https://github.com/FrankHassanabad/suricata-sample-data) ⭐ 37 | 🐛 0 | 🌐 Shell | 📅 2019-01-02 - Repository of creating different example suricata data sets.

## Misc

* [Suriwire](https://github.com/regit/suriwire) ⭐ 95 | 🐛 2 | 🌐 Lua | 📅 2021-11-05 - Wireshark plugin to display Suricata analysis info.
* [SuriGuard](https://github.com/SEc-123/SuriGuard1) ⭐ 21 | 🐛 2 | 🌐 TypeScript | 📅 2025-05-01 - Web-based management system for Suricata IDS/IPS, featuring advanced analytics and visualization capabilities.
* [suriGUI](https://github.com/control-owl/suriGUI) ⚠️ Archived - GUI for Suricata + Qubes OS.
* [bash\_cata](https://github.com/isMTv/bash_cata) ⭐ 9 | 🐛 0 | 🌐 Shell | 📅 2025-12-19 - A simple script that processes the generated Suricata eve-log in real time and, based on alerts, adds an ip-address to the MikroTik Address Lists for a specified time for subsequent blocking.
