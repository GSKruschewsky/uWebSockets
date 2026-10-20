// WebSocket client example: connects, prints the first message and closes.
// Every attempt ends in exactly one of open, rejectedHandshake or connectError.
// The app is a movable handle: holding it in a variable after a chained ws() on a
// temporary (as below) is supported, the callbacks never reference the app object.

#include "ClientApp.h"
#include <iostream>

int main() {
    struct UserData {
        
    };

    uWS::CliApp app = uWS::CliApp()
        .ws<UserData>({
            /* Options */
            .skipUTF8Validation = true,
            .onlyLastPacketFrame = false,

            /* Handlers */
            .open = [](auto *ws) {
                std::cout << "Client is open (attempt " << ws->getClientAttempt() << ")" << std::endl;
            },
            .message = [](auto *ws, std::string_view msg, uWS::OpCode /*opCode*/) {
                std::cout << "Received message: " << msg << std::endl;
                ws->close();
            },
            .close = [](auto */*ws*/, int code, std::string_view reason) {
                std::cout << "Connection closed: " << code << " - " << reason << std::endl;
            },
            .rejectedHandshake = [](std::string_view status, std::string_view statusText, std::string_view /*body*/, uWS::HttpRequest */*req*/, unsigned int attempt) {
                std::cout << "Attempt " << attempt << " handshake rejected: " << status << " " << statusText << std::endl;
            },
            .connectError = [](int code, unsigned int attempt) {
                if (uWS::isConnectErrorResolve(code)) {
                    std::cout << "Attempt " << attempt << " name lookup failed: EAI error " << uWS::connectErrorResolveCode(code) << std::endl;
                } else {
                    std::cout << "Attempt " << attempt << " connect failed: errno " << code << std::endl;
                }
            }
        });

    /* connect(url) resolves the URL's host on a resolver thread and returns the attempt number
     * (ws->getClientAttempt() in open, the last argument of rejectedHandshake / connectError).
     * connect(url, hostname) dials the URL's host (typically an address the caller resolved
     * itself) while sending 'hostname' as the Host header and the TLS SNI, e.g.
     * app.connect("ws://127.0.0.1:3000", "localhost"). Attempts may overlap. */
    unsigned int attempt = app.connect("ws://localhost:3000");
    std::cout << "Started attempt " << attempt << std::endl;
    app.run();

    std::cout << "Client stopped" << std::endl;

    return 0;
}