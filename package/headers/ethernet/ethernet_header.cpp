//
// Created by eduard on 13.12.2020.
//

#include "ethernet_header.h"

ethernet_header::ethernet_header(const ethhdr *ethernet_header)
{
    if(ethernet_header == nullptr)
    {
        return;
    }

    //get the destination address
    destination_mac_address = to_mac(ethernet_header->h_dest);

    //get the source address
    source_mac_address = to_mac(ethernet_header->h_source);

    //set the protocol
    protocol = ethernet_header->h_proto;
}
