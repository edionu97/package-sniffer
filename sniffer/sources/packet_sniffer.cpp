//
// Created by eduard on 13.12.2020.
//

#include <pcap.h>
#include <stdexcept>
#include <functional>
#include <boost/format.hpp>
#include <iostream>

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>    //Provides declarations for icmp header
#include<netinet/udp.h>    //Provides declarations for udp header
#include<netinet/tcp.h>    //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

#include "../headers/packet_sniffer.h"

std::future<void> packet_sniffer::start_package_interception_async(const std::string &interface_name)
{
    return std::async(std::launch::async, [&]()
    {
        try
        {
            //getting all the devices
            char error_buffer[100] = "";

            //open the handle
            pcap_t *pcap_handle;
            if ((pcap_handle = pcap_open_live(interface_name.c_str(), 65536, 1, 0, error_buffer)) == nullptr)
            {
                //get the error message
                const auto error_message = boost::format("Couldn't open the device: %s due to ( %s )")
                                           % interface_name.c_str()
                                           % error_buffer;

                //throw the error
                throw std::runtime_error(error_message.str());
            }

            //write the message
            std::cout << boost::format("Opened the %s for package scanning \n") % interface_name;

            //start the looping
            if (pcap_loop(pcap_handle, -1, on_process_packet, nullptr) < 0)
            {
                //get the error message
                const auto error_message = boost::format("Couldn't open the device: %s due to ( %s )")
                                           % interface_name.c_str()
                                           % error_buffer;

                //throw the error
                throw std::runtime_error(error_message.str());
            }
        }
        catch (std::exception &e)
        {
            std::cout << e.what() << '\n';
        }
    });
}

void packet_sniffer::on_process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
//    //get the ethernet header
//    auto *ethernet_header = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

//    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP)
//    {
//        std::cout << "ARP" << '\n';
//        return;
//    }
//
//    // if is reverse arp
//    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_REVARP)
//    {
//        std::cout << "RVARP" << '\n';
//        return;
//    }

    //get the ip header part of the packet
    auto *ip_header = reinterpret_cast<iphdr *>(const_cast<u_char *>(packet + sizeof(struct ethhdr)));

    //if we do not have the TCP protocol do nothing
    if (ip_header->protocol != 6)
    {
        return;
    }

    //handle the on package intercepted event
    on_packed_intercepted(get_tcp_package(packet));
}

tcp_package packet_sniffer::get_tcp_package(const u_char *packet)
{
    //get the ip header
    const auto ip_header = get_ip_header(packet);

    //get the ip package
    return tcp_package(ip_header,
                       reinterpret_cast<tcphdr *>(
                               const_cast<u_char *>(packet + sizeof(struct ethhdr) + ip_header.ip_header_length)));
}


ethernet_header packet_sniffer::get_ethernet_header(const u_char *packet)
{
    return ethernet_header(reinterpret_cast<ethhdr *>(const_cast<u_char *> (packet)));
}

ip_header packet_sniffer::get_ip_header(const u_char *packet)
{
    //get the ethernet header
    const auto header = get_ethernet_header(packet);

    //create an ip header
    return ip_header(header,
                     reinterpret_cast<iphdr *>(const_cast<u_char *>(packet + sizeof(struct ethhdr))));
}



