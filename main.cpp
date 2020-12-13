/*
	Packet sniffer using libpcap library
*/
#include <pcap.h>
#include <iostream>
#include <nlohmann/json.hpp>

#include "package/generic_package.h"
#include "sniffer/headers/packet_sniffer.h"
#include "server/headers/ws_broadcast_server.h"

#include "utils/nlohmann_json_conversion/convert_to_json.h"

//declare the server
ws_broadcast_server web_socket_broadcast_server{};

/**
 * Implement the on_package intercepted handler
 * @param package : the tcp package
 */
void on_tcp_package_intercepted(tcp_package package)
{
    //generate the json
    nlohmann::json generated_json{{"package", package}};

    //broadcast the message to the client
    web_socket_broadcast_server.broadcast_message(generated_json.dump(4));
}

void on_generic_package_intercepted(generic_package package)
{
//generate the json
    nlohmann::json generated_json{{"package", package}};

    //broadcast the message to the client
    web_socket_broadcast_server.broadcast_message(generated_json.dump(4));
}

int main()
{
    try
    {
        //launch the package interception async and keep the future to avoid locking of the main thead
        auto child_future = packet_sniffer::start_package_interception_async("wlp0s20f3");

        //run the server
        web_socket_broadcast_server.run(9002);
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << '\n';
    }
}