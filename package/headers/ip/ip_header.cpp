//
// Created by eduard on 13.12.2020.
//

#include <cstring>
#include <pcap.h>
#include "ip_header.h"

ip_header::ip_header(const ethernet_header& header, const iphdr *ip_header)
{
    //set the ethernet header
    header_ethernet = header;

    //get the size of the packet
    size_of_packet = ntohs(ip_header->tot_len);

    //set all the other data
    identification = ntohs(ip_header->id);
    ip_version = (unsigned int) ip_header->version;
    ip_header_length = (unsigned int) (ip_header->ihl) * 4; //size in bytes of the header
    type_of_service = (unsigned int) (ip_header->tos);
    ttl = (unsigned int) ip_header->ttl;
    protocol = (unsigned int) ip_header->protocol;
    checksum = ntohs(ip_header->check);

    //set the source and the destination
    source_ip = convert_number_to_ip_address(ip_header->saddr);
    destination_ip = convert_number_to_ip_address(ip_header->daddr);
}

std::string ip_header::convert_number_to_ip_address(unsigned int number)
{
    //declare the sock_address
    sockaddr_in sock_address{};

    //set 0 in each byte
    memset(&sock_address, 0, sizeof(sock_address));

    //set the s_addr in
    sock_address.sin_addr.s_addr = number;

    //convert the address in string
    return std::string{inet_ntoa(sock_address.sin_addr)};
}
