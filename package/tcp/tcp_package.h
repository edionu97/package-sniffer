//
// Created by eduard on 13.12.2020.
//

#ifndef PACKAGE_SNIFFER_TCP_PACKAGE_H
#define PACKAGE_SNIFFER_TCP_PACKAGE_H

#include<netinet/tcp.h>
#include "../headers/ip/ip_header.h"

struct tcp_package
{
    ip_header header_ip {};

    unsigned short source_port{};
    unsigned short destination_port{};
    unsigned short sequence_number{};
    unsigned short acknowledge_number{};
    unsigned int header_length{};

    //flags
    unsigned int urgent_flag{};
    unsigned int acknowledge_flag{};
    unsigned int push_flag{};
    unsigned int reset_flag{};
    unsigned int synchronize_flag{};
    unsigned int finish_flag{};

    unsigned short window{};
    unsigned short checksum{};
    unsigned short urgent_pointer{};

    //payload only if is HTTP
    std::string payload{};
    bool isHttpPackage{};

    //the explicit constructor
    explicit tcp_package() = default;

    /**
     * the tcp package header
     * @param tcp_header
     */
    explicit tcp_package(const ip_header& header, const tcphdr* tcp_header);
};


#endif //PACKAGE_SNIFFER_TCP_PACKAGE_H
