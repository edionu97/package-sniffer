//
// Created by eduard on 13.12.2020.
//

#include "generic_package.h"

generic_package::generic_package(const ip_header &headerIp, unsigned char packageType) : header_ip(headerIp),
                                                                                         package_type(packageType)
{

}
