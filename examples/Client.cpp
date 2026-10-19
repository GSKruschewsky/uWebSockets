// WebSocket client example: connects, prints the first message and closes.
// Every attempt ends in exactly one of open, rejectedHandshake or connectError.

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
            },
            .rejectedHandshake = [](std::string_view status, std::string_view statusText, std::string_view /*body*/, uWS::HttpRequest */*req*/) {
                std::cout << "Handshake rejected: " << status << " " << statusText << std::endl;
            },
            .connectError = [](int code) {
                if (uWS::isConnectErrorResolve(code)) {
                    std::cout << "Name lookup failed: EAI error " << uWS::connectErrorResolveCode(code) << std::endl;
                } else {
                    std::cout << "Connect failed: errno " << code << std::endl;
                }
            }
        })
        /* connect(url) resolves the URL's host on a resolver thread. connect(url, hostname) dials
         * the URL's host (typically an address the caller resolved itself) while sending 'hostname'
         * as the Host header and the TLS SNI, e.g. .connect("ws://127.0.0.1:3000", "localhost") */
        .connect("ws://localhost:3000")
        .run();

    std::cout << "Client stopped" << std::endl;

    return 0;
}