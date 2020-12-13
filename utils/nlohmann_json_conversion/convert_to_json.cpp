//
// Created by eduard on 13.12.2020.
//

#include "convert_to_json.h"

void set_ethernet_and_ip(nlohmann::json &on_json, const ip_header &ip_header)
{
    //get the ip header and set values
    on_json["ip_header"]["ttl"] = ip_header.ttl;
    on_json["ip_header"]["protocol"] = ip_header.protocol;
    on_json["ip_header"]["ip_version"] = ip_header.ip_version;
    on_json["ip_header"]["ip_header_length"] = ip_header.ip_header_length;
    on_json["ip_header"]["type_of_service"] = ip_header.type_of_service;
    on_json["ip_header"]["size_of_packet"] = ip_header.size_of_packet;
    on_json["ip_header"]["identification"] = ip_header.identification;
    on_json["ip_header"]["checksum"] = ip_header.checksum;
    on_json["ip_header"]["source_ip"] = ip_header.source_ip;
    on_json["ip_header"]["destination_ip"] = ip_header.destination_ip;

    //get the eth header and set values
    const auto &eth_header = ip_header.header_ethernet;
    on_json["ip_header"]["eth_header"]["destination_mac_address"] = eth_header.destination_mac_address;
    on_json["ip_header"]["eth_header"]["source_mac_address"] = eth_header.source_mac_address;
    on_json["ip_header"]["eth_header"]["protocol"] = eth_header.protocol;
}

void to_json(nlohmann::json &converted_json, const tcp_package &package)
{
    //set the values for the tcp header
    converted_json = {
            {"package_type",       package.header_ip.protocol},
            {"source_port",        package.source_port},
            {"destination_port",   package.destination_port},
            {"sequence_number",    package.sequence_number},
            {"acknowledge_number", package.acknowledge_number},
            {"header_length",      package.header_length},
            {"urgent_flag",        package.urgent_flag},
            {"acknowledge_flag",   package.acknowledge_flag},
            {"push_flag",          package.push_flag},
            {"reset_flag",         package.reset_flag},
            {"synchronize_flag",   package.synchronize_flag},
            {"finish_flag",        package.finish_flag},
            {"window",             package.window},
            {"checksum",           package.checksum},
            {"urgent_pointer",     package.urgent_pointer},
            {"isHttpPackage",      package.isHttpPackage}
    };

    //set the payload
    if (package.isHttpPackage)
    {
        converted_json["payload"] = package.payload;
    }

    //set the other values (eth and ip)
    set_ethernet_and_ip(converted_json, package.header_ip);
}

void to_json(nlohmann::json &converted_json, const generic_package &package)
{
    //set the values for the tcp header
    converted_json = {
            {"package_type", package.package_type}
    };

    //set the other values (eth and ip)
    set_ethernet_and_ip(converted_json, package.header_ip);
}
