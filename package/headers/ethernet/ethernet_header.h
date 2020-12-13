//
// Created by eduard on 13.12.2020.
//

#ifndef PACKAGE_SNIFFER_ETHERNET_HEADER_H
#define PACKAGE_SNIFFER_ETHERNET_HEADER_H


#include <string>
#include <net/ethernet.h>
#include <boost/format.hpp>

struct ethernet_header
{
    std::string destination_mac_address{};
    std::string source_mac_address{};
    unsigned short protocol{};

    /**
     * The constructor of the object
     * @param ethernet_header: the ethernet header
     */
    explicit ethernet_header(const ethhdr *ethernet_header);

    ethernet_header() = default;

private:

    /**
     * This function it is used for converting an array of bytes into a mac address
     * @param byte_buffer: the byte buffer
     * @return an instance of string
     */
    static std::string to_mac(const unsigned char *byte_buffer)
    {
        std::string mac_address{};

        //iterate through each address byte
        for (auto byte = 0; byte < 6; ++byte)
        {
            //add : after each group of bytes
            if (byte > 0)
            {
                mac_address += ":";
            }

            //convert the value to hex
            const auto value = (boost::format("%02X") %
                                    static_cast<int>(static_cast<unsigned char>(byte_buffer[byte]))).str();

            //append the value
            mac_address += value;
        }

        return mac_address;
    }
};


#endif //PACKAGE_SNIFFER_ETHERNET_HEADER_H
