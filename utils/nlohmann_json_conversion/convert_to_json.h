//
// Created by eduard on 13.12.2020.
//

#ifndef PACKAGE_SNIFFER_CONVERT_TO_JSON_H
#define PACKAGE_SNIFFER_CONVERT_TO_JSON_H

#include <nlohmann/json.hpp>
#include "../../package/headers/ip/ip_header.h"
#include "../../package/tcp/tcp_package.h"
#include "../../package/generic_package.h"

/**
 * Use to set the parameters
 * @param on_json: the json that will be modified
 * @param ip_header: the ip header
 */
void set_ethernet_and_ip(nlohmann::json &on_json, const ip_header &ip_header);

/**
 * Convert the tcp package to json
 * @param converted_json: the json that will be converted
 * @param package: the package itself
 */
void to_json(nlohmann::json &converted_json, const tcp_package &package);

/**
 * Convert the generic package to json
 * @param converted_json: the json that will be converted
 * @param package: the package itself
 */
void to_json(nlohmann::json &converted_json, const generic_package &package);

#endif //PACKAGE_SNIFFER_CONVERT_TO_JSON_H
