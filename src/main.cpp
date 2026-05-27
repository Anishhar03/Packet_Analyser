#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "types.h"

namespace fs = std::filesystem;

using PacketAnalyzer::PacketParser;
using PacketAnalyzer::ParsedPacket;
using PacketAnalyzer::PcapGlobalHeader;
using PacketAnalyzer::PcapPacketHeader;
using PacketAnalyzer::PcapReader;
using PacketAnalyzer::RawPacket;

namespace {

struct CliOptions {
    std::string input_file;
    std::string output_pcap = "reports/filtered.pcap";
    std::string json_report = "reports/analysis.json";
    std::string csv_report = "reports/flows.csv";
    std::string html_report = "reports/dashboard.html";
    std::vector<std::string> rule_files;
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;
    bool write_pcap = true;
    bool write_json = true;
    bool write_csv = true;
    bool write_html = true;
    bool quiet = false;
    int max_packets = -1;
    size_t payload_preview = 24;
};

struct Detection {
    DPI::AppType app = DPI::AppType::UNKNOWN;
    std::string domain;
    std::string method;
    std::vector<std::string> indicators;
};

struct FlowRecord {
    DPI::FiveTuple tuple{};
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t forwarded_packets = 0;
    uint64_t dropped_packets = 0;
    uint32_t first_ts_sec = 0;
    uint32_t first_ts_usec = 0;
    uint32_t last_ts_sec = 0;
    uint32_t last_ts_usec = 0;
    DPI::AppType app = DPI::AppType::UNKNOWN;
    std::string domain;
    std::string detection_method;
    std::string service;
    std::string block_reason;
    bool blocked = false;
    std::set<std::string> indicators;
};

struct AnalysisSummary {
    std::string input_file;
    std::string output_pcap;
    uint64_t packets_seen = 0;
    uint64_t packets_parsed = 0;
    uint64_t parse_errors = 0;
    uint64_t ipv4_packets = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t icmp_packets = 0;
    uint64_t other_packets = 0;
    uint64_t bytes_seen = 0;
    uint64_t forwarded_packets = 0;
    uint64_t dropped_packets = 0;
    uint64_t flows_seen = 0;
    uint32_t first_ts_sec = 0;
    uint32_t first_ts_usec = 0;
    uint32_t last_ts_sec = 0;
    uint32_t last_ts_usec = 0;
};

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool startsWith(const std::string& value, const std::string& prefix) {
    return value.size() >= prefix.size() &&
           value.compare(0, prefix.size(), prefix) == 0;
}

bool endsWith(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string stripLeadingDashes(std::string value) {
    while (!value.empty() && value.front() == '-') {
        value.erase(value.begin());
    }
    return value;
}

std::string jsonEscape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(static_cast<unsigned char>(c));
                } else {
                    out << c;
                }
        }
    }
    return out.str();
}

std::string htmlEscape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
            case '&': out << "&amp;"; break;
            case '<': out << "&lt;"; break;
            case '>': out << "&gt;"; break;
            case '"': out << "&quot;"; break;
            case '\'': out << "&#39;"; break;
            default: out << c;
        }
    }
    return out.str();
}

std::string csvEscape(const std::string& value) {
    bool quote = value.find_first_of(",\"\n\r") != std::string::npos;
    if (!quote) {
        return value;
    }
    std::string escaped = "\"";
    for (char c : value) {
        if (c == '"') {
            escaped += "\"\"";
        } else {
            escaped += c;
        }
    }
    escaped += '"';
    return escaped;
}

bool ensureParentDirectory(const std::string& path) {
    fs::path target(path);
    fs::path parent = target.parent_path();
    if (parent.empty()) {
        return true;
    }
    std::error_code ec;
    fs::create_directories(parent, ec);
    return !ec;
}

uint32_t parseIPv4(const std::string& ip) {
    std::istringstream input(ip);
    std::string part;
    uint32_t result = 0;
    int shift = 0;
    int parts = 0;

    while (std::getline(input, part, '.')) {
        int octet = std::stoi(part);
        if (octet < 0 || octet > 255) {
            throw std::out_of_range("IPv4 octet out of range");
        }
        result |= static_cast<uint32_t>(octet) << shift;
        shift += 8;
        parts++;
    }

    if (parts != 4) {
        throw std::invalid_argument("IPv4 address must have four octets");
    }
    return result;
}

std::string ipToString(uint32_t ip) {
    std::ostringstream out;
    out << ((ip >> 0) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF);
    return out.str();
}

std::string protocolName(uint8_t protocol) {
    if (protocol == PacketAnalyzer::Protocol::TCP) {
        return "TCP";
    }
    if (protocol == PacketAnalyzer::Protocol::UDP) {
        return "UDP";
    }
    if (protocol == PacketAnalyzer::Protocol::ICMP) {
        return "ICMP";
    }
    return "Other(" + std::to_string(protocol) + ")";
}

std::string serviceName(uint16_t port, uint8_t protocol) {
    if (protocol == PacketAnalyzer::Protocol::TCP) {
        switch (port) {
            case 20: return "FTP data";
            case 21: return "FTP control";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS over TCP";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 443: return "HTTPS/TLS";
            case 465: return "SMTPS";
            case 587: return "SMTP submission";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            default: break;
        }
    }

    if (protocol == PacketAnalyzer::Protocol::UDP) {
        switch (port) {
            case 53: return "DNS";
            case 67: return "DHCP server";
            case 68: return "DHCP client";
            case 123: return "NTP";
            case 161: return "SNMP";
            case 443: return "QUIC/HTTP3";
            case 500: return "IKE";
            case 1900: return "SSDP";
            default: break;
        }
    }

    return "";
}

std::string formatTimestamp(uint32_t sec, uint32_t usec) {
    if (sec == 0) {
        return "";
    }
    std::time_t time_value = static_cast<std::time_t>(sec);
    std::tm tm_value{};
#ifdef _WIN32
    localtime_s(&tm_value, &time_value);
#else
    localtime_r(&time_value, &tm_value);
#endif
    std::ostringstream out;
    out << std::put_time(&tm_value, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(6) << std::setfill('0') << usec;
    return out.str();
}

bool isSpecificApp(DPI::AppType app) {
    return app != DPI::AppType::UNKNOWN &&
           app != DPI::AppType::HTTP &&
           app != DPI::AppType::HTTPS &&
           app != DPI::AppType::TLS &&
           app != DPI::AppType::QUIC &&
           app != DPI::AppType::DNS;
}

std::string appAlias(DPI::AppType app) {
    std::string value = toLower(DPI::appTypeToString(app));
    value.erase(std::remove(value.begin(), value.end(), '/'), value.end());
    value.erase(std::remove(value.begin(), value.end(), ' '), value.end());
    return value;
}

DPI::AppType appFromString(const std::string& raw) {
    std::string wanted = toLower(raw);
    wanted.erase(std::remove(wanted.begin(), wanted.end(), '/'), wanted.end());
    wanted.erase(std::remove(wanted.begin(), wanted.end(), ' '), wanted.end());

    if (wanted == "twitter" || wanted == "x") {
        return DPI::AppType::TWITTER;
    }

    for (int i = 0; i < static_cast<int>(DPI::AppType::APP_COUNT); ++i) {
        DPI::AppType app = static_cast<DPI::AppType>(i);
        if (appAlias(app) == wanted) {
            return app;
        }
    }
    return DPI::AppType::UNKNOWN;
}

bool domainMatchesPattern(const std::string& domain_raw, const std::string& pattern_raw) {
    std::string domain = toLower(domain_raw);
    std::string pattern = toLower(pattern_raw);

    if (domain.empty() || pattern.empty()) {
        return false;
    }

    if (startsWith(pattern, "*.") && pattern.size() > 2) {
        std::string suffix = pattern.substr(1);
        return domain == pattern.substr(2) || endsWith(domain, suffix);
    }

    if (startsWith(pattern, "*") && endsWith(pattern, "*") && pattern.size() > 2) {
        return domain.find(pattern.substr(1, pattern.size() - 2)) != std::string::npos;
    }

    if (startsWith(pattern, "*") && pattern.size() > 1) {
        return endsWith(domain, pattern.substr(1));
    }

    if (endsWith(pattern, "*") && pattern.size() > 1) {
        return startsWith(domain, pattern.substr(0, pattern.size() - 1));
    }

    return domain == pattern || endsWith(domain, "." + pattern);
}

std::string payloadPreview(const ParsedPacket& parsed, size_t max_bytes) {
    if (!parsed.payload_data || parsed.payload_length == 0 || max_bytes == 0) {
        return "";
    }

    std::ostringstream out;
    size_t len = std::min(parsed.payload_length, max_bytes);
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        if (i > 0) {
            out << " ";
        }
        out << std::setw(2) << static_cast<int>(parsed.payload_data[i]);
    }
    if (parsed.payload_length > max_bytes) {
        out << " ...";
    }
    return out.str();
}

std::vector<std::string> detectIndicators(const ParsedPacket& parsed) {
    std::vector<std::string> indicators;
    if (!parsed.payload_data || parsed.payload_length == 0) {
        return indicators;
    }

    const auto* data = reinterpret_cast<const char*>(parsed.payload_data);
    std::string sample(data, data + std::min<size_t>(parsed.payload_length, 2048));
    std::string lower = toLower(sample);

    if (lower.find("authorization: basic") != std::string::npos) {
        indicators.push_back("HTTP Basic credentials observed");
    }
    if (lower.find("password=") != std::string::npos ||
        lower.find("passwd=") != std::string::npos ||
        lower.find("pwd=") != std::string::npos) {
        indicators.push_back("Possible password parameter in cleartext");
    }
    if (lower.find("api_key=") != std::string::npos ||
        lower.find("apikey=") != std::string::npos ||
        lower.find("access_token=") != std::string::npos) {
        indicators.push_back("Possible API token in payload");
    }
    if (parsed.has_tcp && parsed.dest_port == 23) {
        indicators.push_back("Telnet traffic is unencrypted");
    }
    if (parsed.has_tcp && parsed.dest_port == 80 && parsed.payload_length > 0) {
        indicators.push_back("Cleartext HTTP payload");
    }

    return indicators;
}

Detection classifyPacket(const ParsedPacket& parsed) {
    Detection detection;

    if (!parsed.has_tcp && !parsed.has_udp) {
        return detection;
    }

    if (parsed.has_tcp && parsed.payload_data && parsed.payload_length > 0) {
        if (parsed.dest_port == 443 || DPI::SNIExtractor::isTLSClientHello(parsed.payload_data, parsed.payload_length)) {
            auto sni = DPI::SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (sni) {
                detection.domain = *sni;
                detection.app = DPI::sniToAppType(*sni);
                detection.method = "TLS SNI";
                return detection;
            }
            if (parsed.dest_port == 443) {
                detection.app = DPI::AppType::HTTPS;
                detection.method = "Port 443 fallback";
            }
        }

        if (parsed.dest_port == 80 || DPI::HTTPHostExtractor::isHTTPRequest(parsed.payload_data, parsed.payload_length)) {
            auto host = DPI::HTTPHostExtractor::extract(parsed.payload_data, parsed.payload_length);
            if (host) {
                detection.domain = *host;
                detection.app = DPI::sniToAppType(*host);
                if (detection.app == DPI::AppType::HTTPS) {
                    detection.app = DPI::AppType::HTTP;
                }
                detection.method = "HTTP Host header";
                return detection;
            }
            if (parsed.dest_port == 80) {
                detection.app = DPI::AppType::HTTP;
                detection.method = "Port 80 fallback";
            }
        }
    }

    if ((parsed.has_udp || parsed.has_tcp) &&
        (parsed.dest_port == 53 || parsed.src_port == 53) &&
        parsed.payload_data && parsed.payload_length > 0) {
        auto query = DPI::DNSExtractor::extractQuery(parsed.payload_data, parsed.payload_length);
        detection.app = DPI::AppType::DNS;
        detection.method = query ? "DNS query" : "Port 53 fallback";
        if (query) {
            detection.domain = *query;
        }
        return detection;
    }

    if (parsed.has_udp && (parsed.dest_port == 443 || parsed.src_port == 443)) {
        detection.app = DPI::AppType::QUIC;
        detection.method = "UDP 443 fallback";
        return detection;
    }

    if (parsed.dest_port == 443 || parsed.src_port == 443) {
        detection.app = DPI::AppType::HTTPS;
        detection.method = "Port 443 fallback";
    } else if (parsed.dest_port == 80 || parsed.src_port == 80) {
        detection.app = DPI::AppType::HTTP;
        detection.method = "Port 80 fallback";
    }

    return detection;
}

class RuleSet {
public:
    void addIP(const std::string& value) {
        blocked_ips_.insert(parseIPv4(value));
    }

    void addApp(const std::string& value) {
        DPI::AppType app = appFromString(value);
        if (app == DPI::AppType::UNKNOWN && toLower(value) != "unknown") {
            throw std::invalid_argument("Unknown application rule: " + value);
        }
        blocked_apps_.insert(appAlias(app));
    }

    void addDomain(const std::string& value) {
        blocked_domains_.push_back(toLower(value));
    }

    void addPort(uint16_t value) {
        blocked_ports_.insert(value);
    }

    std::optional<std::string> match(const ParsedPacket& parsed, const FlowRecord& flow) const {
        if (parsed.has_ip) {
            try {
                uint32_t src = parseIPv4(parsed.src_ip);
                uint32_t dst = parseIPv4(parsed.dest_ip);
                if (blocked_ips_.count(src) > 0) {
                    return "source IP " + parsed.src_ip;
                }
                if (blocked_ips_.count(dst) > 0) {
                    return "destination IP " + parsed.dest_ip;
                }
            } catch (const std::exception&) {
                return std::nullopt;
            }
        }

        if ((parsed.has_tcp || parsed.has_udp) && blocked_ports_.count(parsed.dest_port) > 0) {
            return "destination port " + std::to_string(parsed.dest_port);
        }

        std::string app = appAlias(flow.app);
        if (blocked_apps_.count(app) > 0) {
            return "application " + DPI::appTypeToString(flow.app);
        }

        if (!flow.domain.empty()) {
            for (const auto& pattern : blocked_domains_) {
                if (domainMatchesPattern(flow.domain, pattern)) {
                    return "domain " + flow.domain;
                }
            }
        }

        return std::nullopt;
    }

    bool empty() const {
        return blocked_ips_.empty() && blocked_apps_.empty() &&
               blocked_domains_.empty() && blocked_ports_.empty();
    }

    std::vector<std::string> describe() const {
        std::vector<std::string> rows;
        for (uint32_t ip : blocked_ips_) {
            rows.push_back("IP: " + ipToString(ip));
        }
        for (const auto& app : blocked_apps_) {
            rows.push_back("App: " + app);
        }
        for (const auto& domain : blocked_domains_) {
            rows.push_back("Domain: " + domain);
        }
        for (uint16_t port : blocked_ports_) {
            rows.push_back("Port: " + std::to_string(port));
        }
        return rows;
    }

private:
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<std::string> blocked_apps_;
    std::vector<std::string> blocked_domains_;
    std::unordered_set<uint16_t> blocked_ports_;
};

bool loadRuleFile(const std::string& filename, RuleSet& rules, std::string& error) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        error = "Could not open rule file: " + filename;
        return false;
    }

    std::string section;
    std::string line;
    size_t line_no = 0;
    try {
        while (std::getline(file, line)) {
            line_no++;
            line = trim(line);
            if (line.empty() || startsWith(line, "#") || startsWith(line, "//")) {
                continue;
            }

            if (line.front() == '[' && line.back() == ']') {
                section = toLower(line.substr(1, line.size() - 2));
                continue;
            }

            std::string key;
            std::string value;
            auto eq = line.find('=');
            if (eq != std::string::npos) {
                key = toLower(trim(line.substr(0, eq)));
                value = trim(line.substr(eq + 1));
            } else {
                key = section;
                value = line;
            }

            key = stripLeadingDashes(key);
            if (key == "ip" || key == "block_ip" || key == "blocked_ips" || key == "blocked_ip") {
                rules.addIP(value);
            } else if (key == "app" || key == "block_app" || key == "blocked_apps" || key == "blocked_app") {
                rules.addApp(value);
            } else if (key == "domain" || key == "block_domain" || key == "blocked_domains" || key == "blocked_domain") {
                rules.addDomain(value);
            } else if (key == "port" || key == "block_port" || key == "blocked_ports" || key == "blocked_port") {
                int port = std::stoi(value);
                if (port < 0 || port > 65535) {
                    throw std::out_of_range("port out of range");
                }
                rules.addPort(static_cast<uint16_t>(port));
            } else {
                throw std::invalid_argument("unknown rule key '" + key + "'");
            }
        }
    } catch (const std::exception& ex) {
        error = filename + ":" + std::to_string(line_no) + ": " + ex.what();
        return false;
    }

    return true;
}

void printUsage(const char* program) {
    std::cout << R"(Packet Analyzer - offline DPI, filtering, and reporting

Usage:
  )" << program << R"( analyze <input.pcap> [options]
  )" << program << R"( <input.pcap> [output.pcap] [options]

Core options:
  -o, --output <file>        Write forwarded packets to this PCAP.
  --json <file>              Write a machine-readable JSON report.
  --csv <file>               Write a flow table as CSV.
  --html <file>              Write the visual dashboard report.
  --no-pcap                  Do not write filtered PCAP output.
  --no-json                  Do not write JSON output.
  --no-csv                   Do not write CSV output.
  --no-html                  Do not write HTML output.

Detection and filtering:
  --block-ip <ip>            Drop packets where source or destination IP matches.
  --block-app <app>          Drop detected applications, e.g. YouTube, GitHub.
  --block-domain <pattern>   Drop detected domains, e.g. *.facebook.com.
  --block-port <port>        Drop packets to a destination port.
  --rules <file>             Load rules from a text file.

Runtime controls:
  --max-packets <n>          Stop after n packets.
  --payload-preview <n>      Keep n bytes in CLI previews.
  --quiet                    Reduce console output.
  -h, --help                 Show this help.

Examples:
  )" << program << R"( analyze test_dpi.pcap --block-app YouTube
  )" << program << R"( analyze test_dpi.pcap --block-domain *.tiktok.com --html reports/dashboard.html
  )" << program << R"( test_dpi.pcap filtered.pcap --json reports/analysis.json
)";
}

bool parseCommandLine(int argc, char* argv[], CliOptions& options) {
    if (argc < 2) {
        return false;
    }

    int index = 1;
    std::string first = argv[index];
    if (first == "analyze") {
        index++;
    } else if (first == "-h" || first == "--help" || first == "help") {
        return false;
    }

    if (index >= argc) {
        return false;
    }

    options.input_file = argv[index++];

    if (index < argc && argv[index][0] != '-') {
        options.output_pcap = argv[index++];
        options.write_pcap = true;
    }

    auto requireValue = [&](const std::string& arg) -> std::string {
        if (index >= argc) {
            throw std::invalid_argument(arg + " requires a value");
        }
        return argv[index++];
    };

    while (index < argc) {
        std::string arg = argv[index++];
        if (arg == "-h" || arg == "--help") {
            return false;
        } else if (arg == "-o" || arg == "--output") {
            options.output_pcap = requireValue(arg);
            options.write_pcap = true;
        } else if (arg == "--json") {
            options.json_report = requireValue(arg);
            options.write_json = true;
        } else if (arg == "--csv") {
            options.csv_report = requireValue(arg);
            options.write_csv = true;
        } else if (arg == "--html") {
            options.html_report = requireValue(arg);
            options.write_html = true;
        } else if (arg == "--rules") {
            options.rule_files.push_back(requireValue(arg));
        } else if (arg == "--block-ip") {
            options.block_ips.push_back(requireValue(arg));
        } else if (arg == "--block-app") {
            options.block_apps.push_back(requireValue(arg));
        } else if (arg == "--block-domain") {
            options.block_domains.push_back(requireValue(arg));
        } else if (arg == "--block-port") {
            int port = std::stoi(requireValue(arg));
            if (port < 0 || port > 65535) {
                throw std::out_of_range("port must be between 0 and 65535");
            }
            options.block_ports.push_back(static_cast<uint16_t>(port));
        } else if (arg == "--max-packets") {
            options.max_packets = std::stoi(requireValue(arg));
        } else if (arg == "--payload-preview") {
            int value = std::stoi(requireValue(arg));
            if (value < 0) {
                throw std::out_of_range("payload preview must be non-negative");
            }
            options.payload_preview = static_cast<size_t>(value);
        } else if (arg == "--no-pcap") {
            options.write_pcap = false;
        } else if (arg == "--no-json") {
            options.write_json = false;
        } else if (arg == "--no-csv") {
            options.write_csv = false;
        } else if (arg == "--no-html") {
            options.write_html = false;
        } else if (arg == "--quiet") {
            options.quiet = true;
        } else {
            throw std::invalid_argument("Unknown option: " + arg);
        }
    }

    return true;
}

void applyCliRules(const CliOptions& options, RuleSet& rules) {
    for (const auto& value : options.block_ips) {
        rules.addIP(value);
    }
    for (const auto& value : options.block_apps) {
        rules.addApp(value);
    }
    for (const auto& value : options.block_domains) {
        rules.addDomain(value);
    }
    for (uint16_t value : options.block_ports) {
        rules.addPort(value);
    }
}

void updateFlowClassification(FlowRecord& flow, const Detection& detection) {
    if (!detection.domain.empty() && flow.domain.empty()) {
        flow.domain = detection.domain;
    }
    if (!detection.method.empty() && flow.detection_method.empty()) {
        flow.detection_method = detection.method;
    }

    if (detection.app == DPI::AppType::UNKNOWN) {
        return;
    }

    bool replace = false;
    if (flow.app == DPI::AppType::UNKNOWN) {
        replace = true;
    } else if (!isSpecificApp(flow.app) && isSpecificApp(detection.app)) {
        replace = true;
    } else if ((flow.app == DPI::AppType::HTTP || flow.app == DPI::AppType::HTTPS) &&
               detection.app != flow.app) {
        replace = true;
    }

    if (replace) {
        flow.app = detection.app;
    }
}

void writePcapPacket(std::ofstream& output, const RawPacket& raw) {
    PcapPacketHeader header{};
    header.ts_sec = raw.header.ts_sec;
    header.ts_usec = raw.header.ts_usec;
    header.incl_len = static_cast<uint32_t>(raw.data.size());
    header.orig_len = static_cast<uint32_t>(raw.data.size());
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));
    output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
}

std::vector<FlowRecord> sortedFlows(const std::unordered_map<DPI::FiveTuple, FlowRecord, DPI::FiveTupleHash>& flows) {
    std::vector<FlowRecord> rows;
    rows.reserve(flows.size());
    for (const auto& entry : flows) {
        rows.push_back(entry.second);
    }
    std::sort(rows.begin(), rows.end(), [](const FlowRecord& a, const FlowRecord& b) {
        if (a.bytes != b.bytes) {
            return a.bytes > b.bytes;
        }
        if (a.packets != b.packets) {
            return a.packets > b.packets;
        }
        return a.first_ts_sec < b.first_ts_sec;
    });
    return rows;
}

std::map<std::string, uint64_t> aggregateByApp(const std::vector<FlowRecord>& flows) {
    std::map<std::string, uint64_t> result;
    for (const auto& flow : flows) {
        result[DPI::appTypeToString(flow.app)] += flow.packets;
    }
    return result;
}

std::vector<std::pair<std::string, uint64_t>> topDomains(const std::vector<FlowRecord>& flows, size_t limit) {
    std::unordered_map<std::string, uint64_t> counts;
    for (const auto& flow : flows) {
        if (!flow.domain.empty()) {
            counts[flow.domain] += flow.packets;
        }
    }

    std::vector<std::pair<std::string, uint64_t>> rows(counts.begin(), counts.end());
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return a.first < b.first;
    });
    if (rows.size() > limit) {
        rows.resize(limit);
    }
    return rows;
}

bool writeJsonReport(const std::string& path,
                     const AnalysisSummary& summary,
                     const RuleSet& rules,
                     const std::vector<FlowRecord>& flows) {
    if (!ensureParentDirectory(path)) {
        return false;
    }
    std::ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    out << "{\n";
    out << "  \"summary\": {\n";
    out << "    \"input_file\": \"" << jsonEscape(summary.input_file) << "\",\n";
    out << "    \"output_pcap\": \"" << jsonEscape(summary.output_pcap) << "\",\n";
    out << "    \"packets_seen\": " << summary.packets_seen << ",\n";
    out << "    \"packets_parsed\": " << summary.packets_parsed << ",\n";
    out << "    \"parse_errors\": " << summary.parse_errors << ",\n";
    out << "    \"bytes_seen\": " << summary.bytes_seen << ",\n";
    out << "    \"ipv4_packets\": " << summary.ipv4_packets << ",\n";
    out << "    \"tcp_packets\": " << summary.tcp_packets << ",\n";
    out << "    \"udp_packets\": " << summary.udp_packets << ",\n";
    out << "    \"icmp_packets\": " << summary.icmp_packets << ",\n";
    out << "    \"other_packets\": " << summary.other_packets << ",\n";
    out << "    \"forwarded_packets\": " << summary.forwarded_packets << ",\n";
    out << "    \"dropped_packets\": " << summary.dropped_packets << ",\n";
    out << "    \"flows_seen\": " << summary.flows_seen << ",\n";
    out << "    \"first_seen\": \"" << jsonEscape(formatTimestamp(summary.first_ts_sec, summary.first_ts_usec)) << "\",\n";
    out << "    \"last_seen\": \"" << jsonEscape(formatTimestamp(summary.last_ts_sec, summary.last_ts_usec)) << "\"\n";
    out << "  },\n";

    out << "  \"rules\": [";
    auto rule_descriptions = rules.describe();
    for (size_t i = 0; i < rule_descriptions.size(); ++i) {
        if (i > 0) {
            out << ", ";
        }
        out << "\"" << jsonEscape(rule_descriptions[i]) << "\"";
    }
    out << "],\n";

    out << "  \"flows\": [\n";
    for (size_t i = 0; i < flows.size(); ++i) {
        const auto& flow = flows[i];
        out << "    {\n";
        out << "      \"src_ip\": \"" << jsonEscape(flow.src_ip) << "\",\n";
        out << "      \"src_port\": " << flow.src_port << ",\n";
        out << "      \"dst_ip\": \"" << jsonEscape(flow.dst_ip) << "\",\n";
        out << "      \"dst_port\": " << flow.dst_port << ",\n";
        out << "      \"protocol\": \"" << jsonEscape(protocolName(flow.protocol)) << "\",\n";
        out << "      \"service\": \"" << jsonEscape(flow.service) << "\",\n";
        out << "      \"app\": \"" << jsonEscape(DPI::appTypeToString(flow.app)) << "\",\n";
        out << "      \"domain\": \"" << jsonEscape(flow.domain) << "\",\n";
        out << "      \"detection_method\": \"" << jsonEscape(flow.detection_method) << "\",\n";
        out << "      \"packets\": " << flow.packets << ",\n";
        out << "      \"bytes\": " << flow.bytes << ",\n";
        out << "      \"forwarded_packets\": " << flow.forwarded_packets << ",\n";
        out << "      \"dropped_packets\": " << flow.dropped_packets << ",\n";
        out << "      \"blocked\": " << (flow.blocked ? "true" : "false") << ",\n";
        out << "      \"block_reason\": \"" << jsonEscape(flow.block_reason) << "\",\n";
        out << "      \"first_seen\": \"" << jsonEscape(formatTimestamp(flow.first_ts_sec, flow.first_ts_usec)) << "\",\n";
        out << "      \"last_seen\": \"" << jsonEscape(formatTimestamp(flow.last_ts_sec, flow.last_ts_usec)) << "\",\n";
        out << "      \"indicators\": [";
        size_t indicator_index = 0;
        for (const auto& indicator : flow.indicators) {
            if (indicator_index++ > 0) {
                out << ", ";
            }
            out << "\"" << jsonEscape(indicator) << "\"";
        }
        out << "]\n";
        out << "    }" << (i + 1 == flows.size() ? "\n" : ",\n");
    }
    out << "  ]\n";
    out << "}\n";
    return true;
}

bool writeCsvReport(const std::string& path, const std::vector<FlowRecord>& flows) {
    if (!ensureParentDirectory(path)) {
        return false;
    }
    std::ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    out << "src_ip,src_port,dst_ip,dst_port,protocol,service,app,domain,detection_method,packets,bytes,forwarded_packets,dropped_packets,blocked,block_reason,first_seen,last_seen,indicators\n";
    for (const auto& flow : flows) {
        std::string indicators;
        for (const auto& indicator : flow.indicators) {
            if (!indicators.empty()) {
                indicators += "; ";
            }
            indicators += indicator;
        }
        out << csvEscape(flow.src_ip) << ","
            << flow.src_port << ","
            << csvEscape(flow.dst_ip) << ","
            << flow.dst_port << ","
            << csvEscape(protocolName(flow.protocol)) << ","
            << csvEscape(flow.service) << ","
            << csvEscape(DPI::appTypeToString(flow.app)) << ","
            << csvEscape(flow.domain) << ","
            << csvEscape(flow.detection_method) << ","
            << flow.packets << ","
            << flow.bytes << ","
            << flow.forwarded_packets << ","
            << flow.dropped_packets << ","
            << (flow.blocked ? "true" : "false") << ","
            << csvEscape(flow.block_reason) << ","
            << csvEscape(formatTimestamp(flow.first_ts_sec, flow.first_ts_usec)) << ","
            << csvEscape(formatTimestamp(flow.last_ts_sec, flow.last_ts_usec)) << ","
            << csvEscape(indicators) << "\n";
    }
    return true;
}

std::string badgeClassForFlow(const FlowRecord& flow) {
    if (flow.blocked) {
        return "bad";
    }
    if (!flow.indicators.empty()) {
        return "warn";
    }
    if (isSpecificApp(flow.app)) {
        return "good";
    }
    return "neutral";
}

bool writeHtmlReport(const std::string& path,
                     const AnalysisSummary& summary,
                     const RuleSet& rules,
                     const std::vector<FlowRecord>& flows) {
    if (!ensureParentDirectory(path)) {
        return false;
    }
    std::ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    auto app_counts = aggregateByApp(flows);
    auto domains = topDomains(flows, 12);
    uint64_t max_app = 1;
    for (const auto& entry : app_counts) {
        max_app = std::max(max_app, entry.second);
    }

    out << R"(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Packet Analyzer Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17202a;
      --muted: #687282;
      --line: #d9dee7;
      --panel: #ffffff;
      --page: #f5f7fb;
      --accent: #1d7a8c;
      --green: #19764b;
      --red: #b42318;
      --amber: #9a6700;
      --violet: #6046b6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, Segoe UI, Roboto, Arial, sans-serif;
      background: var(--page);
      color: var(--ink);
      letter-spacing: 0;
    }
    header {
      background: #18212f;
      color: #fff;
      padding: 28px clamp(18px, 4vw, 48px);
      border-bottom: 5px solid var(--accent);
    }
    header h1 { margin: 0 0 8px; font-size: clamp(28px, 4vw, 44px); font-weight: 760; }
    header p { margin: 0; color: #c8d3df; max-width: 980px; line-height: 1.5; }
    main { padding: 22px clamp(14px, 4vw, 48px) 44px; }
    .grid { display: grid; gap: 14px; }
    .stats { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); margin-bottom: 18px; }
    .stat {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      min-height: 92px;
    }
    .stat span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 700; }
    .stat strong { display: block; margin-top: 8px; font-size: 26px; }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin-top: 16px;
    }
    section h2 { margin: 0 0 14px; font-size: 18px; }
    .split { grid-template-columns: minmax(0, 1.15fr) minmax(280px, 0.85fr); }
    @media (max-width: 900px) { .split { grid-template-columns: 1fr; } }
    .bar-row { display: grid; grid-template-columns: 160px 1fr 72px; gap: 12px; align-items: center; margin: 10px 0; }
    .bar-label { color: var(--ink); font-weight: 650; overflow-wrap: anywhere; }
    .bar-track { height: 12px; background: #edf1f6; border-radius: 99px; overflow: hidden; }
    .bar-fill { height: 100%; background: var(--accent); }
    .bar-count { color: var(--muted); text-align: right; font-variant-numeric: tabular-nums; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 12px; }
    input, select {
      height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 12px;
      background: #fff;
      min-width: 180px;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid var(--line); padding: 10px 8px; text-align: left; vertical-align: top; }
    th { color: #354255; background: #f7f9fc; position: sticky; top: 0; z-index: 1; }
    tbody tr:hover { background: #f8fbfd; }
    .table-wrap { overflow: auto; max-height: 620px; border: 1px solid var(--line); border-radius: 8px; }
    .badge { display: inline-block; border-radius: 999px; padding: 4px 9px; font-size: 12px; font-weight: 700; }
    .good { background: #e8f5ee; color: var(--green); }
    .bad { background: #fdecec; color: var(--red); }
    .warn { background: #fff4d6; color: var(--amber); }
    .neutral { background: #eef1f6; color: #4b5563; }
    .rules { display: flex; flex-wrap: wrap; gap: 8px; }
    .rules span { background: #eef7f9; color: #155e6e; border: 1px solid #c5e3e9; border-radius: 999px; padding: 6px 10px; font-size: 12px; font-weight: 700; }
    .muted { color: var(--muted); }
    .nowrap { white-space: nowrap; }
  </style>
</head>
<body>
  <header>
    <h1>Packet Analyzer Dashboard</h1>
    <p>Offline DPI report for )" << htmlEscape(summary.input_file) << R"(. The dashboard summarizes protocol mix, detected applications, domains, blocked flows, and suspicious payload indicators.</p>
  </header>
  <main>
    <div class="grid stats">
)";

    auto stat = [&](const std::string& label, uint64_t value) {
        out << "      <div class=\"stat\"><span>" << htmlEscape(label) << "</span><strong>"
            << value << "</strong></div>\n";
    };
    stat("Packets Seen", summary.packets_seen);
    stat("Flows", summary.flows_seen);
    stat("Forwarded", summary.forwarded_packets);
    stat("Dropped", summary.dropped_packets);
    stat("TCP", summary.tcp_packets);
    stat("UDP", summary.udp_packets);

    out << R"(    </div>
    <section>
      <h2>Run Context</h2>
      <p class="muted">First packet: )" << htmlEscape(formatTimestamp(summary.first_ts_sec, summary.first_ts_usec))
        << R"( | Last packet: )" << htmlEscape(formatTimestamp(summary.last_ts_sec, summary.last_ts_usec))
        << R"( | Output PCAP: )" << htmlEscape(summary.output_pcap) << R"(</p>
      <div class="rules">
)";
    auto rule_descriptions = rules.describe();
    if (rule_descriptions.empty()) {
        out << "        <span>No blocking rules enabled</span>\n";
    } else {
        for (const auto& rule : rule_descriptions) {
            out << "        <span>" << htmlEscape(rule) << "</span>\n";
        }
    }

    out << R"(      </div>
    </section>
    <div class="grid split">
      <section>
        <h2>Application Distribution</h2>
)";
    for (const auto& [app, count] : app_counts) {
        double width = (100.0 * static_cast<double>(count)) / static_cast<double>(max_app);
        out << "        <div class=\"bar-row\"><div class=\"bar-label\">" << htmlEscape(app)
            << "</div><div class=\"bar-track\"><div class=\"bar-fill\" style=\"width:"
            << std::fixed << std::setprecision(1) << width
            << "%\"></div></div><div class=\"bar-count\">" << count << "</div></div>\n";
    }

    out << R"(      </section>
      <section>
        <h2>Top Domains</h2>
)";
    if (domains.empty()) {
        out << "        <p class=\"muted\">No DNS, HTTP Host, or TLS SNI domains were detected.</p>\n";
    } else {
        out << "        <table><thead><tr><th>Domain</th><th>Packets</th></tr></thead><tbody>\n";
        for (const auto& [domain, count] : domains) {
            out << "          <tr><td>" << htmlEscape(domain) << "</td><td class=\"nowrap\">" << count << "</td></tr>\n";
        }
        out << "        </tbody></table>\n";
    }

    out << R"(      </section>
    </div>
    <section>
      <h2>Flow Table</h2>
      <div class="toolbar">
        <input id="search" placeholder="Search IP, domain, app, reason">
        <select id="verdict">
          <option value="">All verdicts</option>
          <option value="blocked">Blocked only</option>
          <option value="allowed">Allowed only</option>
          <option value="flagged">Flagged only</option>
        </select>
      </div>
      <div class="table-wrap">
        <table id="flows">
          <thead>
            <tr>
              <th>Verdict</th><th>Source</th><th>Destination</th><th>Protocol</th>
              <th>Application</th><th>Domain</th><th>Packets</th><th>Bytes</th><th>Reason / Indicators</th>
            </tr>
          </thead>
          <tbody>
)";

    for (const auto& flow : flows) {
        std::string text = flow.src_ip + " " + flow.dst_ip + " " + DPI::appTypeToString(flow.app) + " " +
                           flow.domain + " " + flow.block_reason;
        for (const auto& indicator : flow.indicators) {
            text += " " + indicator;
        }
        std::string verdict = flow.blocked ? "blocked" : (flow.indicators.empty() ? "allowed" : "flagged");
        std::string badge = badgeClassForFlow(flow);
        std::string reason = flow.block_reason;
        for (const auto& indicator : flow.indicators) {
            if (!reason.empty()) {
                reason += "; ";
            }
            reason += indicator;
        }
        if (reason.empty()) {
            reason = "No rule hit";
        }

        out << "            <tr data-verdict=\"" << verdict << "\" data-search=\""
            << htmlEscape(toLower(text)) << "\">"
            << "<td><span class=\"badge " << badge << "\">" << (flow.blocked ? "Blocked" : (flow.indicators.empty() ? "Allowed" : "Flagged")) << "</span></td>"
            << "<td>" << htmlEscape(flow.src_ip) << ":" << flow.src_port << "</td>"
            << "<td>" << htmlEscape(flow.dst_ip) << ":" << flow.dst_port << "</td>"
            << "<td>" << htmlEscape(protocolName(flow.protocol)) << "<br><span class=\"muted\">" << htmlEscape(flow.service) << "</span></td>"
            << "<td>" << htmlEscape(DPI::appTypeToString(flow.app)) << "<br><span class=\"muted\">" << htmlEscape(flow.detection_method) << "</span></td>"
            << "<td>" << htmlEscape(flow.domain) << "</td>"
            << "<td class=\"nowrap\">" << flow.packets << "</td>"
            << "<td class=\"nowrap\">" << flow.bytes << "</td>"
            << "<td>" << htmlEscape(reason) << "</td>"
            << "</tr>\n";
    }

    out << R"(          </tbody>
        </table>
      </div>
    </section>
  </main>
  <script>
    const search = document.getElementById('search');
    const verdict = document.getElementById('verdict');
    const rows = Array.from(document.querySelectorAll('#flows tbody tr'));
    function applyFilters() {
      const q = search.value.trim().toLowerCase();
      const v = verdict.value;
      rows.forEach(row => {
        const matchesText = !q || row.dataset.search.includes(q);
        const matchesVerdict = !v || row.dataset.verdict === v;
        row.style.display = matchesText && matchesVerdict ? '' : 'none';
      });
    }
    search.addEventListener('input', applyFilters);
    verdict.addEventListener('change', applyFilters);
  </script>
</body>
</html>
)";

    return true;
}

bool analyze(const CliOptions& options, const RuleSet& rules) {
    PcapReader reader;
    if (!reader.open(options.input_file)) {
        return false;
    }

    std::ofstream output_pcap;
    if (options.write_pcap) {
        if (!ensureParentDirectory(options.output_pcap)) {
            std::cerr << "Error: Could not create output directory for " << options.output_pcap << "\n";
            return false;
        }
        output_pcap.open(options.output_pcap, std::ios::binary);
        if (!output_pcap.is_open()) {
            std::cerr << "Error: Could not open output PCAP: " << options.output_pcap << "\n";
            return false;
        }

        PcapGlobalHeader header = reader.getGlobalHeader();
        header.magic_number = 0xa1b2c3d4;
        output_pcap.write(reinterpret_cast<const char*>(&header), sizeof(header));
    }

    AnalysisSummary summary;
    summary.input_file = options.input_file;
    summary.output_pcap = options.write_pcap ? options.output_pcap : "";

    std::unordered_map<DPI::FiveTuple, FlowRecord, DPI::FiveTupleHash> flows;
    RawPacket raw;
    ParsedPacket parsed;

    if (!options.quiet) {
        std::cout << "Analyzing " << options.input_file << "\n";
        if (!rules.empty()) {
            std::cout << "Blocking rules enabled: " << rules.describe().size() << "\n";
        }
    }

    while (reader.readNextPacket(raw)) {
        if (options.max_packets > 0 && summary.packets_seen >= static_cast<uint64_t>(options.max_packets)) {
            break;
        }

        summary.packets_seen++;
        summary.bytes_seen += raw.data.size();
        if (summary.first_ts_sec == 0) {
            summary.first_ts_sec = raw.header.ts_sec;
            summary.first_ts_usec = raw.header.ts_usec;
        }
        summary.last_ts_sec = raw.header.ts_sec;
        summary.last_ts_usec = raw.header.ts_usec;

        if (!PacketParser::parse(raw, parsed)) {
            summary.parse_errors++;
            if (options.write_pcap) {
                writePcapPacket(output_pcap, raw);
            }
            summary.forwarded_packets++;
            continue;
        }

        summary.packets_parsed++;

        if (parsed.has_ip) {
            summary.ipv4_packets++;
        }
        if (parsed.has_tcp) {
            summary.tcp_packets++;
        } else if (parsed.has_udp) {
            summary.udp_packets++;
        } else if (parsed.has_ip && parsed.protocol == PacketAnalyzer::Protocol::ICMP) {
            summary.icmp_packets++;
        } else {
            summary.other_packets++;
        }

        bool drop_packet = false;

        if (parsed.has_ip && (parsed.has_tcp || parsed.has_udp)) {
            DPI::FiveTuple tuple{};
            tuple.src_ip = parseIPv4(parsed.src_ip);
            tuple.dst_ip = parseIPv4(parsed.dest_ip);
            tuple.src_port = parsed.src_port;
            tuple.dst_port = parsed.dest_port;
            tuple.protocol = parsed.protocol;

            auto& flow = flows[tuple];
            if (flow.packets == 0) {
                flow.tuple = tuple;
                flow.src_ip = parsed.src_ip;
                flow.dst_ip = parsed.dest_ip;
                flow.src_port = parsed.src_port;
                flow.dst_port = parsed.dest_port;
                flow.protocol = parsed.protocol;
                flow.first_ts_sec = raw.header.ts_sec;
                flow.first_ts_usec = raw.header.ts_usec;
                flow.service = serviceName(parsed.dest_port, parsed.protocol);
            }

            flow.packets++;
            flow.bytes += raw.data.size();
            flow.last_ts_sec = raw.header.ts_sec;
            flow.last_ts_usec = raw.header.ts_usec;

            Detection detection = classifyPacket(parsed);
            updateFlowClassification(flow, detection);
            for (const auto& indicator : detectIndicators(parsed)) {
                flow.indicators.insert(indicator);
            }

            if (flow.service.empty()) {
                flow.service = serviceName(parsed.dest_port, parsed.protocol);
            }

            if (!flow.blocked) {
                auto reason = rules.match(parsed, flow);
                if (reason) {
                    flow.blocked = true;
                    flow.block_reason = *reason;
                }
            }

            drop_packet = flow.blocked;
            if (drop_packet) {
                flow.dropped_packets++;
            } else {
                flow.forwarded_packets++;
            }

            if (!options.quiet && summary.packets_seen <= 12) {
                std::cout << "#" << summary.packets_seen << " "
                          << parsed.src_ip << ":" << parsed.src_port
                          << " -> " << parsed.dest_ip << ":" << parsed.dest_port
                          << " " << protocolName(parsed.protocol)
                          << " app=" << DPI::appTypeToString(flow.app);
                if (!flow.domain.empty()) {
                    std::cout << " domain=" << flow.domain;
                }
                if (!flow.block_reason.empty()) {
                    std::cout << " blocked=" << flow.block_reason;
                }
                std::string preview = payloadPreview(parsed, options.payload_preview);
                if (!preview.empty()) {
                    std::cout << " payload=" << preview;
                }
                std::cout << "\n";
            }
        }

        if (drop_packet) {
            summary.dropped_packets++;
        } else {
            if (options.write_pcap) {
                writePcapPacket(output_pcap, raw);
            }
            summary.forwarded_packets++;
        }
    }

    reader.close();
    if (output_pcap.is_open()) {
        output_pcap.close();
    }

    auto flows_vector = sortedFlows(flows);
    summary.flows_seen = flows_vector.size();

    bool ok = true;
    if (options.write_json && !writeJsonReport(options.json_report, summary, rules, flows_vector)) {
        std::cerr << "Error: Could not write JSON report: " << options.json_report << "\n";
        ok = false;
    }
    if (options.write_csv && !writeCsvReport(options.csv_report, flows_vector)) {
        std::cerr << "Error: Could not write CSV report: " << options.csv_report << "\n";
        ok = false;
    }
    if (options.write_html && !writeHtmlReport(options.html_report, summary, rules, flows_vector)) {
        std::cerr << "Error: Could not write HTML report: " << options.html_report << "\n";
        ok = false;
    }

    std::cout << "\nAnalysis complete\n";
    std::cout << "  Packets seen:      " << summary.packets_seen << "\n";
    std::cout << "  Parsed packets:    " << summary.packets_parsed << "\n";
    std::cout << "  Flows:             " << summary.flows_seen << "\n";
    std::cout << "  Forwarded packets: " << summary.forwarded_packets << "\n";
    std::cout << "  Dropped packets:   " << summary.dropped_packets << "\n";
    if (options.write_pcap) {
        std::cout << "  Filtered PCAP:     " << options.output_pcap << "\n";
    }
    if (options.write_html) {
        std::cout << "  Dashboard:         " << options.html_report << "\n";
    }
    if (options.write_json) {
        std::cout << "  JSON report:       " << options.json_report << "\n";
    }
    if (options.write_csv) {
        std::cout << "  CSV report:        " << options.csv_report << "\n";
    }

    return ok;
}

} // namespace

int main(int argc, char* argv[]) {
    CliOptions options;

    try {
        if (!parseCommandLine(argc, argv, options)) {
            printUsage(argv[0]);
            return argc < 2 ? 1 : 0;
        }

        RuleSet rules;
        for (const auto& file : options.rule_files) {
            std::string error;
            if (!loadRuleFile(file, rules, error)) {
                std::cerr << "Error: " << error << "\n";
                return 1;
            }
        }
        applyCliRules(options, rules);

        return analyze(options, rules) ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n\n";
        printUsage(argv[0]);
        return 1;
    }
}
