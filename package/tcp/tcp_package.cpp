//
// Created by eduard on 13.12.2020.
//

#include "tcp_package.h"

tcp_package::tcp_package(const ip_header &header, const tcphdr *tcp_header)
{
    //set the ip header
    header_ip = header;

    //set the other values
    source_port = ntohs(tcp_header->source);
    destination_port = ntohs(tcp_header->dest);
    sequence_number = ntohl(tcp_header->seq);
    acknowledge_number = ntohl(tcp_header->ack_seq);
    header_length = (unsigned int)(tcp_header->doff) * 4; //size in bytes (DWORDs to bytes)

    //flags
    urgent_flag = (unsigned int)(tcp_header->urg);
    acknowledge_flag = (unsigned int)(tcp_header->ack);
    push_flag = (unsigned int)(tcp_header->psh);
    reset_flag = (unsigned int)(tcp_header->rst);
    synchronize_flag = (unsigned int)(tcp_header->syn);
    finish_flag = (unsigned int)(tcp_header->fin);

    window = ntohs(tcp_header->window);
    window = ntohs(tcp_header->check);
    urgent_pointer = tcp_header->urg_ptr;
}
