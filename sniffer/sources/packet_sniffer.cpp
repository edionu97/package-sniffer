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
#include "../../package/generic_package.h"

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
    //get the ethernet header
    const auto *ethernet_header = reinterpret_cast<ether_header *>(const_cast<u_char *>(packet));

    // if is undefined
    if (ntohs(ethernet_header->ether_type) == 8200)
    {
        std::cout << "Undefined protocol\n";
        return;
    }

    //get the ip header part of the packet
    const auto *ip_header = reinterpret_cast<iphdr *>(const_cast<u_char *>(packet + sizeof(struct ethhdr)));

    //process the tcp package
    if (ip_header->protocol == 6)
    {
        //handle the on package intercepted event
        on_tcp_package_intercepted(get_tcp_package(packet, header->len));
        return;
    }

    //get the ip header
    auto eth_header = get_ip_header(packet);

    //generate the generic package
    generic_package generic_package{eth_header, ip_header->protocol};

    //call the handler
    on_generic_package_intercepted(generic_package);
}

tcp_package packet_sniffer::get_tcp_package(const u_char *packet, int total_package_size)
{
    //get the ip header
    const auto ip_header = get_ip_header(packet);

    //get the tcp package
    auto tcp = tcp_package(ip_header,
                           reinterpret_cast<tcphdr *>(
                                   const_cast<u_char *>(packet + sizeof(struct ethhdr) + ip_header.ip_header_length)));

    //the package is http only in this situation
    tcp.isHttpPackage = tcp.destination_port == 80;

    //if is http package
    if (tcp.isHttpPackage)
    {
        //get the number of bytes to read
        auto *icmp_header = (struct icmphdr *) (packet + ip_header.ip_header_length + sizeof(struct ethhdr));
        auto tcp_header_size = sizeof(struct ethhdr) + ip_header.ip_header_length + sizeof icmp_header;

        //set the payload
        tcp.payload = get_http_payload(packet + tcp_header_size, total_package_size - tcp_header_size);
    }

    //get the ip package
    return tcp;
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

std::string packet_sniffer::get_http_payload(const u_char *data_buffer, int size)
{
    std::string payload{};

    //iterate through data
    for (auto i = 0; i < size; ++i)
    {
        payload += (boost::format("%02X ")
                    % static_cast<int>(static_cast<unsigned char>(data_buffer[i]))).str();
    }

    //set the payload
    return payload;
}



