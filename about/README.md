# About This Project

This folder explains the major concepts used by Packet Analyzer. Read the files in order if you are learning the project from zero.

1. [Networking Basics](01_networking_basics.md)
2. [PCAP and Packet Parsing](02_pcap_and_packet_parsing.md)
3. [Deep Packet Inspection](03_deep_packet_inspection.md)
4. [Application Detection](04_application_detection.md)
5. [Flow Tracking and Rules](05_flow_tracking_and_rules.md)
6. [Reports, UI, Build, and CI](06_reports_ui_build_ci.md)

The short version: a PCAP stores raw captured packets, the C++ parser extracts network-layer fields, the DPI logic inspects visible application metadata, the rule engine decides whether a flow should be allowed or blocked, and the reporting layer turns the result into PCAP, JSON, CSV, and HTML artifacts.
