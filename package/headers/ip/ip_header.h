//
// Created by eduard on 13.12.2020.
//

#ifndef PACKAGE_SNIFFER_IP_HEADER_H
#define PACKAGE_SNIFFER_IP_HEADER_H

#include<netinet/ip.h>
#include "../ethernet/ethernet_header.h"

struct ip_header
{
    //an ip header contains an ethernet header
    ethernet_header header_ethernet;

    unsigned int ttl{};
    unsigned int protocol{};
    unsigned int ip_version{};
    unsigned int ip_header_length{};
    unsigned int type_of_service{};

    unsigned short int size_of_packet{};
    unsigned short int identification{};
    unsigned short int checksum{};

    std::string source_ip{};
    std::string destination_ip{};

    /**
     * This represents the explicit constructor for the ip header
     * @param packet: the packet
     * @param pcap_packet_size: the size of the packet
     */
    explicit ip_header(const ethernet_header &header, const iphdr *ip_header);

    /**
     * Default constructor
     */
    explicit ip_header() = default;

private:

    /**
     * Convert a number to an ip address
     * @param number: the number we want to convert
     * @return a string representing the ip header
     */
    static std::string convert_number_to_ip_address(unsigned int number);
};


#endif //PACKAGE_SNIFFER_IP_HEADER_H
