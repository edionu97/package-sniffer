//
// Created by eduard on 13.12.2020.
//

#include "../headers/ws_broadcast_server.h"
#include <boost/format.hpp>


ws_broadcast_server::ws_broadcast_server()
{
    //stop the logging from the frame_header and the frame_payload
    asio_server_.clear_access_channels(websocketpp::log::alevel::frame_header | websocketpp::log::alevel::frame_payload);

    //init the asio
    asio_server_.init_asio();

    //set the handlers
    asio_server_.set_open_handler(bind(&ws_broadcast_server::on_open_handler, this, ::_1));
    asio_server_.set_close_handler(bind(&ws_broadcast_server::on_close_handler, this, ::_1));
    asio_server_.set_message_handler(bind(&ws_broadcast_server::on_message_handler, this, ::_1, ::_2));
}

void ws_broadcast_server::run(unsigned run_on_port)
{
    std::cout << boost::format("Starting the server on localhost: %d\n") % run_on_port;

    // Listen on port 9002
    asio_server_.listen(run_on_port);

    // Queues a connection accept operation
    asio_server_.start_accept();

    //run the server
    try
    {
        // Start the Asio io_service run loop
        asio_server_.run();
    } catch (const std::exception &e)
    {
        std::cout << e.what() << '\n';
    }
}

void ws_broadcast_server::on_open_handler(const connection_hdl &handler)
{
    //this is a critical section
    {
        //lock the mutex
        std::lock_guard<std::mutex> guard(clients_mutex_);
        //insert the message into connected clients queue
        connected_clients_.insert(handler);
    }
}

void ws_broadcast_server::on_close_handler(const connection_hdl &handler)
{
    //this is a critical section
    {
        //lock the mutex
        std::lock_guard<std::mutex> guard(clients_mutex_);

        //remove items from collection
        connected_clients_.erase(handler);

        std::cout << connected_clients_.size() << '\n';
    }
}

void ws_broadcast_server::on_message_handler(const connection_hdl &handler, const server::message_ptr &message)
{
    for (const auto &client : connected_clients_)
    {
        asio_server_.send(client, message);
    }
}

void ws_broadcast_server::broadcast_message(const std::string &message)
{
    //critical section
    {
        //lock the mutex
        std::lock_guard<std::mutex> guard(clients_mutex_);

        //iterate though connected clients
        for (const auto &client : connected_clients_)
        {
            try
            {
                asio_server_.send(client, message, websocketpp::frame::opcode::text);
            }
            catch (const std::exception &e)
            {
                std::cout << e.what() << '\n';
            }
        }
    }
}

ws_broadcast_server::~ws_broadcast_server()
{
    for (const auto &child_process: child_processes_)
    {
        child_process.wait();
    }
}