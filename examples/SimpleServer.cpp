#include <App.h>
#include <iostream>

int main() {
    /* ws->getUserData returns one of these */
    struct PerSocketData {
        std::string ip;
    };

    /* Keep in mind that uWS::SSLApp({options}) is the same as uWS::App() when compiled without SSL support.
     * You may swap to using uWS:App() if you don't need SSL */
    
     uWS::App()
        .ws<PerSocketData>("/*", {
            /* Handlers */
            .upgrade = [](auto *res, auto *req, auto *context) {
                // Get remote IP as text during upgrade
                std::string ip(res->getRemoteAddressAsText());

                // You MUST copy any data you want to keep
                PerSocketData data{ip};

                // Perform the upgrade and attach PerSocketData
                res->template upgrade<PerSocketData>(
                    std::move(data),
                    req->getHeader("sec-websocket-key"),
                    req->getHeader("sec-websocket-protocol"),
                    req->getHeader("sec-websocket-extensions"),
                    context
                );
            },
            .open = [](auto *ws) {
                /* Open event here, you may access ws->getUserData() which points to a PerSocketData struct */
                auto *data = (PerSocketData *) ws->getUserData();
                std::cout << "Client connected from: " << data->ip << '\n' << std::endl;
                ws->send(data->ip, uWS::OpCode::TEXT);

            },
            .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) {
                /* This is the opposite of what you probably want; compress if message is LARGER than 16 kb
                * the reason we do the opposite here; compress if SMALLER than 16 kb is to allow for
                * benchmarking of large message sending without compression */

                /* Never mind, it changed back to never compressing for now */
                std::cout << "Received message from client:\n" << message << "\nSending it back...\n" << std::endl;
                ws->send(message, opCode, false);
            },
            .dropped = [](auto */*ws*/, std::string_view /*message*/, uWS::OpCode /*opCode*/) {
                /* A message was dropped due to set maxBackpressure and closeOnBackpressureLimit limit */
            },
            .drain = [](auto */*ws*/) {
                /* Check ws->getBufferedAmount() here */
            },
            .ping = [](auto */*ws*/, std::string_view) {
                /* Not implemented yet */
            },
            .pong = [](auto */*ws*/, std::string_view) {
                /* Not implemented yet */
            },
            .close = [](auto */*ws*/, int /*code*/, std::string_view /*message*/) {
                /* You may access ws->getUserData() here */
            }
        })
        .listen("0.0.0.0", 3000, [](auto *token) {
            if (token) {
                std::cout << "Server started on 'localhost:3000'.\n " << std::endl;
            } else {
                std::cout << "Failed to listen on port 3000" << std::endl;
            }
        })
        .run();

    std::cout << "Server stopped" << std::endl;
    return 0;
}