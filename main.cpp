#include <iostream>
#include <pcap.h>
#include <cstring>

#ifdef _WIN32
#include <Winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#endif

struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

struct ip_header {
    uint8_t version_and_header_length;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t src_ip_addr[4];
    uint8_t dest_ip_addr[4];
};

class NPcapHandler {
private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE]{};

    std::string interface_name;
    struct bpf_program filter{};
    bpf_u_int32 net, mask;

    std::string src_ip;
    std::string src_mac;

    static ethernet_header construct_ethernet_header(const std::string& src_mac, const std::string& dest_mac) {

        ethernet_header header{};
        sscanf(dest_mac.c_str(), "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &header.dest_mac[0], &header.dest_mac[1], &header.dest_mac[2],
               &header.dest_mac[3], &header.dest_mac[4], &header.dest_mac[5]);

        sscanf(src_mac.c_str(), "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
               &header.src_mac[0], &header.src_mac[1], &header.src_mac[2],
               &header.src_mac[3], &header.src_mac[4], &header.src_mac[5]);

        header.ether_type = htons(0x0800); // IPv4

        return header;
    }

    static ip_header construct_ip_header(const std::string& src_ip, const std::string& dest_ip, size_t payloadSize) {
        ip_header header{};
        
        header.version_and_header_length = 0x45;
        header.type_of_service = 0;
        header.total_length = htons(sizeof(ip_header) + sizeof(udp_header) + payloadSize);
        header.identification = 0;
        header.flags_and_fragment_offset = 0;
        header.time_to_live = 128;
        header.protocol = IPPROTO_UDP;
        header.header_checksum = 0;

        #ifdef _WIN32
            header.src_ip_addr[0] = inet_addr(src_ip.c_str());
            header.dest_ip_addr[0] = inet_addr(dest_ip.c_str());
        #else
            inet_pton(AF_INET, src_ip.c_str(), header.src_ip_addr);
            inet_pton(AF_INET, dest_ip.c_str(), header.dest_ip_addr);
        #endif

        return header;
    }

    static udp_header construct_udp_header(const int src_port, const int dest_port, size_t payload_size) {
        udp_header header{};
        header.src_port = htons(src_port);
        header.dest_port = htons(dest_port);
        header.length = htons(sizeof(udp_header) + payload_size);
        header.checksum = 0;

        return header;
    }

    static void construct_udp_buffer(u_char* packet_buffer, ethernet_header &eth_header, ip_header &ip_header, udp_header &udp_header, const u_char* payload, size_t payload_size) {
        memcpy(packet_buffer, &eth_header, sizeof(ethernet_header));
        memcpy(packet_buffer + sizeof(ethernet_header), &ip_header, sizeof(ip_header));
        memcpy(packet_buffer + sizeof(ethernet_header) + sizeof(ip_header), &udp_header, sizeof(udp_header));
        memcpy(packet_buffer + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header), payload, payload_size);
    }
    

public:

    std::string interfaceName;

    NPcapHandler() : handle(nullptr) {}

    ~NPcapHandler() {
        close_channel();
    }

    bool open_channel(const std::string& iface_name, int port_for_read) {
        this->interface_name = iface_name;
        this->handle = pcap_open_live(iface_name.c_str(), 65536, 1, 1000, this->errbuf);
        if (handle == nullptr) return false;

        if (pcap_lookupnet(iface_name.c_str(), &this->net, &this->mask, errbuf) == -1) {
            std::cerr << "Error in obtaining the IP address and subnet mask for the device " << iface_name << ": " << errbuf << std::endl;
            return false;
        }

        std::string filter_expression = "udp port " + std::to_string(port_for_read);
        if (pcap_compile(this->handle, &this->filter, filter_expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) < 0) {
            std::cerr << "Error compiling filter: " << pcap_geterr(this->handle) << std::endl;
            return false;
        }
        if (pcap_setfilter(this->handle, &this->filter) < 0) {
            std::cerr << "Error setting filter: " << pcap_geterr(this->handle) << std::endl;
            return false;
        }

        return true;
    }

    u_char* read() {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(this->handle, &header, &data);

        if (res < 0) {
            return nullptr;
        }

        auto* packet = new u_char[header->caplen];
        memcpy(packet, data, header->caplen);

        return packet;
    }

    void write(const std::string& src_ip, const std::string& dest_ip, const std::string& src_mac, const std::string& dest_mac, const int src_port, const int dest_port, const u_char* payload) {
        size_t payload_size = strlen(reinterpret_cast<const char*>(payload));

        ethernet_header eth_header = construct_ethernet_header(src_mac, dest_mac);
        ip_header ip_header = construct_ip_header(src_ip, dest_ip, payload_size);
        udp_header udp_header = construct_udp_header(src_port, dest_port, payload_size);

        u_char packet_buffer[sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header) + payload_size];
        construct_udp_buffer(packet_buffer, eth_header, ip_header, udp_header, payload, payload_size);

        if (pcap_sendpacket(this->handle, reinterpret_cast<const uint8_t*>(packet_buffer), sizeof(packet_buffer)) != 0) {
            std::cerr << "Error sending packet: " << pcap_geterr(this->handle) << std::endl;
        }

    }

    void close_channel() {
        if (handle != nullptr) {
            pcap_freecode(&this->filter);
            pcap_close(handle);
            handle = nullptr;
            interfaceName.clear();
        }
    }

};

int main() {
    NPcapHandler pcapInterface;

    if (!pcapInterface.open_channel("wlo1", 24)) {
        std::cerr << "Failed to open channel on pcapInterface." << std::endl;
        return 1;
    }

    int cnt = 0;
    while (cnt < 3) {
        auto* packet = (u_char *) "Hello, world";
        if (packet != nullptr) {
            std::cout << "Send a packet." << std::endl;
            pcapInterface.write("192.168.1.69", "192.168.1.69", "c8:94:02:41:b4:f1",  "c8:94:02:41:b4:f1", 24, 23, packet);
            cnt += 1;
        }
    }

    // Close the channel when done
    pcapInterface.close_channel();

    return 0;

}
