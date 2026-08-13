#ifndef UWS_CLI_APP_H
#define UWS_CLI_APP_H

#include <string>
#include <charconv>
#include <string_view>
#include <sstream>

/* An app is a convenience wrapper of some of the most used fuctionalities and allows a
 * builder-pattern kind of init. Apps operate on the implicit thread local Loop */

#include "HttpContext.h"
#include "HttpResponse.h"
#include "WebSocketContext.h"
#include "WebSocket.h"
#include "PerMessageDeflate.h"

namespace uWS {

    /* This one matches us_socket_context_options_t but has default values */
    struct ClientSocketContextOptions {
        const char *key_file_name = nullptr;
        const char *cert_file_name = nullptr;
        const char *passphrase = nullptr;
        const char *dh_params_file_name = nullptr;
        const char *ca_file_name = nullptr;
        const char *ssl_ciphers = nullptr;
        int ssl_prefer_low_memory_usage = 0;

        /* Conversion operator used internally */
        operator struct us_socket_context_options_t() const {
            struct us_socket_context_options_t socket_context_options;
            memcpy(&socket_context_options, this, sizeof(ClientSocketContextOptions));
            return socket_context_options;
        }
    };

    static_assert(sizeof(struct us_socket_context_options_t) == sizeof(ClientSocketContextOptions), "Mismatching uSockets/uWebSockets ABI");
    
template <bool SSL>
struct TemplatedClientApp {
private:
    /* The app always owns at least one http context, but creates websocket contexts on demand */
    HttpContext<SSL> *httpContext;
    
    char webSocketKey[24];
    bool handshakeSent = false;

    int port;
    std::string path;
    std::string host;
    char *source_host;
    std::unordered_map<std::string, std::string> customHeaders;

public:

    TemplatedClientApp(ClientSocketContextOptions options = {}) {
        httpContext = HttpContext<SSL>::create(Loop::get(), options);

        if (httpContext) {
            /* A connect that fails before opening (refused, unreachable) reaches
             * neither on_open nor on_close — uSockets delivers it here. Without a
             * registered handler uSockets has nowhere to report the failure. Note
             * that the socket is a dead semi-socket: its ext is uninitialized, so
             * only the context may be touched. */
            us_socket_context_on_connect_error(SSL, (struct us_socket_context_t *) httpContext, [](struct us_socket_t *s, int code) {
                HttpContextData<SSL> *httpContextData = HttpContext<SSL>::getSocketContextDataS(s);
                if (httpContextData->clientConnectErrorHandler) {
                    httpContextData->clientConnectErrorHandler(code);
                } else if (httpContextData->clientHandshakeAbortedHandler) {
                    /* No connectError registered: report through rejectedHandshake so the
                     * failure is never silent */
                    httpContextData->clientHandshakeAbortedHandler(std::string_view("", 0));
                }
                return s;
            });
        }
    }

    bool constructorFailed() {
        return !httpContext;
    }

    template <typename UserData>
    struct WebSocketBehavior {
        /* Disabled compression by default - probably a bad default */
        CompressOptions compression = DISABLED;
        /* Maximum message size we can receive */
        unsigned int maxPayloadLength = 16 * 1024;
        /* 2 minutes timeout is good */
        unsigned short idleTimeout = 120;
        /* 64kb backpressure is probably good */
        unsigned int maxBackpressure = 64 * 1024;
        bool closeOnBackpressureLimit = false;
        /* This one depends on kernel timeouts and is a bad default */
        bool resetIdleTimeoutOnSend = false;
        /* A good default, esp. for newcomers */
        bool sendPingsAutomatically = true;
        /* Custom aditional options (Client-specific) */
        bool skipUTF8Validation = false;
        bool onlyLastPacketFrame = false;
        std::unordered_map<std::string, std::string> customHeaders = {};
        char *localAddress = nullptr;
        /* Maximum socket lifetime in minutes before forced closure (defaults to disabled) */
        unsigned short maxLifetime = 0;
        MoveOnlyFunction<void(HttpResponse<SSL> *, HttpRequest *, struct us_socket_context_t *)> upgrade = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *)> open = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view, OpCode)> message = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view, OpCode)> dropped = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *)> drain = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view)> ping = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view)> pong = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, std::string_view, int, int)> subscription = nullptr;
        MoveOnlyFunction<void(WebSocket<SSL, false, UserData> *, int, std::string_view)> close = nullptr;
        MoveOnlyFunction<void(std::string_view, std::string_view, std::string_view, HttpRequest *)> rejectedHandshake = nullptr;
        /* Called when the TCP connection itself fails (refused, unreachable, resolution
         * failure) — before any of open/close/rejectedHandshake could apply. The code is
         * the platform errno (e.g. ECONNREFUSED), or 0 when no attempt could be made. */
        MoveOnlyFunction<void(int)> connectError = nullptr;
    };

    /* Returns the SSL_CTX of this app, or nullptr. */
    void *getNativeHandle() {
        return us_socket_context_get_native_handle(SSL, (struct us_socket_context_t *) httpContext);
    }

    template <typename UserData>
    TemplatedClientApp &&ws(WebSocketBehavior<UserData> &&behavior) {
        /* Don't compile if alignment rules cannot be satisfied */
        static_assert(alignof(UserData) <= LIBUS_EXT_ALIGNMENT,
        "µWebSockets cannot satisfy UserData alignment requirements. You need to recompile µSockets with LIBUS_EXT_ALIGNMENT adjusted accordingly.");

        if (!httpContext) {
            return std::move(static_cast<TemplatedClientApp &&>(*this));
        }

        /* Terminate on misleading idleTimeout values */
        if (behavior.idleTimeout && behavior.idleTimeout < 8) {
            std::cerr << "Error: idleTimeout must be either 0 or greater than 8!" << std::endl;
            std::terminate();
        }

        /* Maximum idleTimeout is 16 minutes */
        if (behavior.idleTimeout > 240 * 4) {
            std::cerr << "Error: idleTimeout must not be greater than 960 seconds!" << std::endl;
            std::terminate();
        }

        /* Maximum maxLifetime is 4 hours */
        if (behavior.maxLifetime > 240) {
            std::cerr << "Error: maxLifetime must not be greater than 240 minutes!" << std::endl;
            std::terminate();
        }

        auto *webSocketContext = WebSocketContext<SSL, false, UserData>::create(Loop::get(), (us_socket_context_t *) httpContext, nullptr);

        /* Quick fix to disable any compression if set */
#ifdef UWS_NO_ZLIB
        behavior.compression = DISABLED;
#endif

        /* If we are the first one to use compression, initialize it */
        if (behavior.compression) {
            LoopData *loopData = (LoopData *) us_loop_ext(us_socket_context_loop(SSL, webSocketContext->getSocketContext()));

            /* Initialize loop's deflate inflate streams */
            if (!loopData->zlibContext) {
                loopData->zlibContext = new ZlibContext;
                loopData->inflationStream = new InflationStream(CompressOptions::DEDICATED_DECOMPRESSOR);
                loopData->deflationStream = new DeflationStream(CompressOptions::DEDICATED_COMPRESSOR);
            }
        }

        /* Copy all handlers */
        webSocketContext->getExt()->openHandler = std::move(behavior.open);
        webSocketContext->getExt()->messageHandler = std::move(behavior.message);
        webSocketContext->getExt()->droppedHandler = std::move(behavior.dropped);
        webSocketContext->getExt()->drainHandler = std::move(behavior.drain);
        webSocketContext->getExt()->subscriptionHandler = std::move(behavior.subscription);
        webSocketContext->getExt()->closeHandler = std::move(behavior.close);
        webSocketContext->getExt()->pingHandler = std::move(behavior.ping);
        webSocketContext->getExt()->pongHandler = std::move(behavior.pong);
        webSocketContext->getExt()->rejectedHandshakeHandler = std::move(behavior.rejectedHandshake);

        /* Connect errors happen while the socket still belongs to the HTTP context,
         * so this handler lives there rather than on the WebSocket context. Must be
         * taken out of behavior before the onHttp lambdas below move the rest of it. */
        httpContext->getSocketContextData()->clientConnectErrorHandler = std::move(behavior.connectError);

        /* Catch-all for attempts that die without a parsed rejection (refused with no
         * connectError registered, reset, timed out, or an unparseable response): route
         * them to rejectedHandshake so every failed connect reaches the app. Empty
         * status/text mean "no HTTP response"; body carries any raw bytes received. */
        httpContext->getSocketContextData()->clientHandshakeAbortedHandler = [webSocketContext](std::string_view rawResponse) {
            WebSocketContextData<SSL, false, UserData> *webSocketContextData = (WebSocketContextData<SSL, false, UserData> *) us_socket_context_ext(SSL, (us_socket_context_t *) webSocketContext);
            if (webSocketContextData->rejectedHandshakeHandler) {
                /* There is no request to expose; hand out an inert empty one */
                HttpRequest emptyRequest;
                webSocketContextData->rejectedHandshakeHandler(std::string_view("", 0), std::string_view("", 0), rawResponse, &emptyRequest);
            }
        };

        /* Copy settings */
        webSocketContext->getExt()->maxPayloadLength = behavior.maxPayloadLength;
        webSocketContext->getExt()->maxBackpressure = behavior.maxBackpressure;
        webSocketContext->getExt()->closeOnBackpressureLimit = behavior.closeOnBackpressureLimit;
        webSocketContext->getExt()->resetIdleTimeoutOnSend = behavior.resetIdleTimeoutOnSend;
        webSocketContext->getExt()->sendPingsAutomatically = behavior.sendPingsAutomatically;
        webSocketContext->getExt()->maxLifetime = behavior.maxLifetime;
        webSocketContext->getExt()->compression = behavior.compression;
        
        /* Custom aditional options (Client-specific) */
        webSocketContext->getExt()->skipUTF8Validation = behavior.skipUTF8Validation;
        webSocketContext->getExt()->onlyLastPacketFrame = behavior.onlyLastPacketFrame;
        this->customHeaders = std::move(behavior.customHeaders);
        this->source_host = behavior.localAddress;

        /* Calculate idleTimeoutCompnents */
        webSocketContext->getExt()->calculateIdleTimeoutCompnents(behavior.idleTimeout);

        /* 
         * Filter is called only when the connection opens (event = 1) or 
         * closes (event = -1) of the socket. So we set a filter to send 
         * the initial websocket handshake once the server connection is open. 
         */
        httpContext->filter([ this ](HttpResponse<SSL> *res, int event) {
            if (event == 1) {
                /* Connection established */
                if (!this->handshakeSent) {
                    this->handshakeSent = true;

                    /* Writes a new key to "this->webSocketKey" */
                    WebSocketHandshake::generateKey(this->webSocketKey);

                    res->writeInitHandshake(
                        this->host, 
                        this->path, 
                        this->webSocketKey,
                        this->customHeaders
                    );
                }
            } else if (event == -1) {
                /* Connection closed */
                if (this->handshakeSent) {
                    this->handshakeSent = false;
                }
            }
        });
        
        /* Creates a "fake" route to handle the server initial handshake successful response. */
        httpContext->onHttp("HTTP/1.1", "101", [this, webSocketContext, behavior = std::move(behavior)](HttpResponse<SSL> *res, HttpRequest *req) mutable {
            
            /* If we have this header set, it's a websocket handshake response */
            std::string_view secWebSocketAccept = req->getHeader("sec-websocket-accept");
            if (secWebSocketAccept.length() != 28) {
                /* Tell the router that we did not handle this request */
                req->setYield(true);
                return;
            }
            
            char expectedSecWebSocketAccept[29] = {};
            WebSocketHandshake::generate(this->webSocketKey, expectedSecWebSocketAccept);
            if (memcmp(secWebSocketAccept.data(), expectedSecWebSocketAccept, 28) != 0) {
                /* Tell the router that we did not handle this request */
                req->setYield(true);
                return;
            }

            /* Emit upgrade handler */
            if (behavior.upgrade) {
                behavior.upgrade(res, req, (struct us_socket_context_t *) webSocketContext);
            } else {
                /* Default handler upgrades to WebSocket */
                res->template upgradeClient<UserData>(
                    {}, 
                    {}, 
                    req->getHeader("sec-websocket-protocol"), 
                    req->getHeader("sec-websocket-extensions"), 
                    (struct us_socket_context_t *) webSocketContext
                );
            }

            /* We are going to get uncorked by the Http get return */

            /* We do not need to check for any close or shutdown here as we immediately return from get handler */

        }, true);
        
        /* Creates a "fake" route to handle the server initial handshake NOT successful response. */
        httpContext->onHttp("HTTP/1.1", "/*", [this, webSocketContext, behavior = std::move(behavior)](HttpResponse<SSL> *res, HttpRequest *req) mutable {
            /* This is the one terminal callback for this attempt; the close fallback
             * below (triggered by us_socket_close) must stay quiet */
            HttpResponseData<SSL> *httpResponseData = (HttpResponseData<SSL> *) us_socket_ext(SSL, (us_socket_t *) res);
            httpResponseData->clientCallbackDelivered = true;

            WebSocketContextData<SSL, false, UserData> *webSocketContextData = (WebSocketContextData<SSL, false, UserData> *) us_socket_context_ext(SSL, (us_socket_context_t *) webSocketContext);
            if (webSocketContextData->rejectedHandshakeHandler) {
                /* Deliver while the socket is still alive: status, headers and body are
                 * views into this socket's parser buffers and die with it on close */
                std::string_view status = req->getFullUrl();
                std::string_view statusText = req->getHeader(status);
                HttpContextData<SSL> *httpContextData = this->httpContext->getSocketContextData();
                std::string_view body {
                    httpContextData->reqRemaningData,
                    httpContextData->reqRemaningDataLen
                };
                webSocketContextData->rejectedHandshakeHandler(
                    status,
                    statusText,
                    body,
                    req
                );
            }

            /* Close this socket */
            us_socket_shutdown(SSL, (us_socket_t *) res);
            /* Close any socket on HTTP errors */
            us_socket_close(SSL, (us_socket_t *) res, 0, nullptr);

        }, false);
        
        return std::move(static_cast<TemplatedClientApp &&>(*this));
    }

    TemplatedClientApp &&connect(std::string url) {
        /* Starting a new connection cycle: re-arm the handshake. 'handshakeSent'
         * dedups the handshake among the filter lambdas registered by ws() calls
         * (all of them fire per socket open), so it must be armed once per
         * connection attempt. The filter's own reset (event == -1) only covers
         * sockets closed while still owned by the HTTP context — after a
         * successful 101 upgrade the socket belongs to the WebSocket context, so
         * a normal WebSocket close leaves the flag set and, without this reset,
         * any further connect() would establish TCP but never send a handshake. */
        handshakeSent = false;

        /* Parses the URL setting "host", "path" and "port" */

        // Check protocol and validate against SSL setting
        if (url.rfind("wss://", 0) == 0) {
            if (!SSL) {
                 throw std::runtime_error("WebSocket client SSL is disabled but URL uses \"wss://\".");
            }
            url = url.substr(6);
        } else if (url.rfind("ws://", 0) == 0) {
            if (SSL) {
                throw std::runtime_error("WebSocket client SSL is enabled but URL uses \"ws://\".");
            }
            url = url.substr(5);
        }
        
        // Set default port based on protocol
        port = SSL ? 443 : 80;
        
        // Find the first occurrence of '/' or '?' to separate host:port from path
        size_t pathStart = url.find_first_of("/?");
        std::string hostPort = url.substr(0, pathStart);
        
        // Extract path (everything after host:port, including query string)
        if (pathStart != std::string::npos) {
            path = "/" + url.substr(pathStart + 1);
            // Handle the case where path starts with '?'
            if (url[pathStart] == '?') {
                path = "/?" + url.substr(pathStart + 1);
            } else {
                path = url.substr(pathStart);
            }
        } else {
            path = "/";
        }
        
        // Parse host and port
        size_t colon = hostPort.find(':');
        if (colon != std::string::npos) {
            host = hostPort.substr(0, colon);
            port = std::stoi(hostPort.substr(colon + 1));
        } else {
            host = hostPort;
        }

        /* Connect the socket */
        us_socket_t *connectSocket = httpContext->connect(host.c_str(), port, 0, this->source_host);

        if (!connectSocket) {
            /* The connect failed synchronously (name resolution or socket creation) so
             * no socket exists to report the error through. Deliver the callback from a
             * one-shot timer rather than synchronously or via Loop::defer: the caller
             * observes every connect failure asynchronously and cannot recurse through
             * a retrying handler, while the timer (unlike a deferred lambda) is a poll
             * that keeps the loop alive until delivery. The context pointer is carried
             * in the timer ext since the app itself may be moved by the builder chain. */
            struct us_timer_t *connectErrorTimer = us_create_timer((struct us_loop_t *) Loop::get(), 0, sizeof(HttpContext<SSL> *));
            *(HttpContext<SSL> **) us_timer_ext(connectErrorTimer) = httpContext;
            us_timer_set(connectErrorTimer, [](struct us_timer_t *t) {
                HttpContext<SSL> *localHttpContext = *(HttpContext<SSL> **) us_timer_ext(t);
                us_timer_close(t);

                HttpContextData<SSL> *httpContextData = localHttpContext->getSocketContextData();
                if (httpContextData->clientConnectErrorHandler) {
                    httpContextData->clientConnectErrorHandler(0);
                } else if (httpContextData->clientHandshakeAbortedHandler) {
                    /* No connectError registered: report through rejectedHandshake */
                    httpContextData->clientHandshakeAbortedHandler(std::string_view("", 0));
                }
            }, 1, 0);

            return std::move(static_cast<TemplatedClientApp &&>(*this));
        }

        /* Set client side SNI (It will do nothing if not 'SSL') */
        us_socket_context_set_host_name(SSL, (struct us_socket_context_t *) httpContext, host.c_str());

        return std::move(static_cast<TemplatedClientApp &&>(*this));
    }

    TemplatedClientApp &&run() {
        uWS::run();
        return std::move(static_cast<TemplatedClientApp &&>(*this));
    }
};

};

namespace uWS {
    typedef uWS::TemplatedClientApp<false> CliApp;
    typedef uWS::TemplatedClientApp<true> CliSSLApp;
}

#endif // UWS_CLI_APP_H
