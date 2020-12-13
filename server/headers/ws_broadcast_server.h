//
// Created by eduard on 13.12.2020.
//

#ifndef PACKAGE_SNIFFER_WS_BROADCAST_SERVER_H
#define PACKAGE_SNIFFER_WS_BROADCAST_SERVER_H


#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <set>

#include <functional>


typedef websocketpp::server<websocketpp::config::asio> server;

using websocketpp::connection_hdl;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;


class ws_broadcast_server
{
public:
    /**
     * Constructs the websocket service
     */
    ws_broadcast_server();

    /**
     * Starts the ws service
     * @param run_on_port: the port on which the server will run
     */
    void run(unsigned run_on_port);

    /**
     * This method it is used for sending a message to all the connected clients
     * @param message: the message that will be send
     */
    void broadcast_message(const std::string& message);

    /**
     * The destructor
     */
    ~ws_broadcast_server();

private:


    /**
     * This callback will be called when a user connects to the websocket
     * @param handler : the client handler
     */
    void on_open_handler(const connection_hdl& handler);

    /**
     * This handler will be called when the client disconnects from the server
     * @param handler: the client handler
     */
    void on_close_handler(const connection_hdl& handler);

    /**
     * This handler will be called when a client send a message to the server
     * @param handler: the client handler
     * @param message: the message
     */
    void on_message_handler(const connection_hdl& handler, const server::message_ptr& message);

    //the server
    server asio_server_;

    //this represents the connected clients list
    std::set<connection_hdl, std::owner_less<connection_hdl>> connected_clients_;

    //create the mutex for clients concurrent connection
    std::mutex clients_mutex_;

    //array of child prcesses
    std::vector<std::future<void>> child_processes_;
};

#endif //PACKAGE_SNIFFER_WS_BROADCAST_SERVER_H
