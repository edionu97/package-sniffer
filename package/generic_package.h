//
// Created by eduard on 13.12.2020.
//

#ifndef PACKAGE_SNIFFER_GENERIC_PACKAGE_H
#define PACKAGE_SNIFFER_GENERIC_PACKAGE_H


#include "headers/ethernet/ethernet_header.h"
#include "headers/ip/ip_header.h"

struct generic_package
{
    ip_header header_ip{};
    unsigned char package_type{};

    explicit generic_package(const ip_header &headerIp, unsigned char packageType);
};


#endif //PACKAGE_SNIFFER_GENERIC_PACKAGE_H
