//
// Created by eduard on 13.12.2020.
//

#pragma  once

#ifndef PACKAGE_SNIFFER_PACKET_SNIFFER_H
#define PACKAGE_SNIFFER_PACKET_SNIFFER_H


#include <string>
#include <future>
#include "../../package/headers/ethernet/ethernet_header.h"
#include "../../package/headers/ip/ip_header.h"
#include "../../package/tcp/tcp_package.h"
#include "../../package/generic_package.h"

/**
 * Handler for on_packed intercepted
 * @param package: the package
 */
void on_tcp_package_intercepted(tcp_package package);

/**
 * This method handles the generic package message
 * @param package: the package
 */
void on_generic_package_intercepted(generic_package package);

class packet_sniffer
{
public:

    /**
     * This method it is used for starting the package sniffer
     */
    static std::future<void> start_package_interception_async(const std::string &interface_name);

private:

    /**
     * This function represents the package handler
     * @param args: the pcap loop arguments (null)
     * @param header: the package header
     * @param packet: the packet itself
     */
    static void on_process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    /**
     * This function it is used for getting the tcp package
     * @param packet: the packet
     * @return an instance of tcp package
     */
    static tcp_package get_tcp_package(const u_char *packet, int total_package_size);

    /**
     * This function it is used for getting the ethernet header
     * @param packet: the the packet
     * @return: an instance of ethernet header
     */
    static ethernet_header get_ethernet_header(const u_char *packet);

    /**
     * This function it is used for getting the ip header
     * @param packet: the packet itself
     * @return an instance of the ip_header
     */
    static ip_header get_ip_header(const u_char *packet);

    static std::string get_http_payload(const u_char* data_buffer, int size);
};


#endif //PACKAGE_SNIFFER_PACKET_SNIFFER_H
