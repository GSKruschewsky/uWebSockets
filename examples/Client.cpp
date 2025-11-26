// This example is broken and doesn't do anything. It is a potential interface for a future potential client.
// There is no client support implemented in the library. This example is a placeholder.

#include "ClientApp.h"
#include <iostream>

int main() {
    struct UserData {
        
    };

    uWS::CliApp()
        .ws<UserData>({
            /* Options */
            .skipUTF8Validation = true,
            .onlyLastPacketFrame = false,

            /* Handlers */
            .open = [](auto */*ws*/) {
                std::cout << "Client is open" << std::endl;
            },
            .message = [](auto *ws, std::string_view msg, uWS::OpCode /*opCode*/) {
                std::cout << "Received message: " << msg << std::endl;
                ws->close();
            },
            .close = [](auto */*ws*/, int code, std::string_view reason) {
                std::cout << "Connection closed: " << code << " - " << reason << std::endl;
            }
        })
        .connect("ws://localhost:3000")
        .run();

    std::cout << "Client stopped" << std::endl;

    return 0;
}