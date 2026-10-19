/*
 * Authored by Alex Hultman, 2018-2020.
 * Intellectual property of third-party.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UWS_HTTPCONTEXTDATA_H
#define UWS_HTTPCONTEXTDATA_H

#include "HttpRouter.h"

#include <vector>
#include <unordered_map>
#include <string>
#include "MoveOnlyFunction.h"

namespace uWS {
template<bool> struct HttpResponse;
struct HttpRequest;

template <bool SSL>
struct alignas(16) HttpContextData {
    template <bool> friend struct HttpContext;
    template <bool> friend struct HttpResponse;
    template <bool> friend struct TemplatedApp;
    template <bool> friend struct TemplatedClientApp;
private:
    std::vector<MoveOnlyFunction<void(HttpResponse<SSL> *, int)>> filterHandlers;

    MoveOnlyFunction<void(const char *hostname)> missingServerNameHandler;

    /* Client-side only: invoked when an outgoing connection fails before it opens
     * (refused, unreachable, resolution failure, connect timeout). Errors at that stage
     * reach neither on_open nor on_close, so they need their own channel to the app.
     * The second argument is the attempt the failure belongs to (see clientAttempts). */
    MoveOnlyFunction<void(int, unsigned int)> clientConnectErrorHandler = nullptr;

    /* Client-side only: catch-all for connect attempts that die without a parsed
     * rejection - refused with no connectError registered, reset, timed out, or an
     * unparseable response. Receives whatever raw response bytes were buffered and
     * the attempt. Guarantees every failed attempt reaches the app exactly once. */
    MoveOnlyFunction<void(std::string_view, unsigned int)> clientHandshakeAbortedHandler = nullptr;

    /* Client-side only: what each connect() attempt must send once its socket opens, keyed by
     * the socket uSockets returned (stable from connect() through on_open, also while a name
     * lookup is in flight). Attempts may overlap, so none of this can live on the app. An entry
     * is consumed by the handshake filter on open and dropped on a connect error or timeout. */
    struct ClientAttempt {
        unsigned int id;
        std::string hostHeader;
        std::string path;
        std::string sniHost;
    };
    std::unordered_map<us_socket_t *, ClientAttempt> clientAttempts;

    /* Forgets the attempt of a socket that will never open and returns its id (0 if unknown) */
    unsigned int dropClientAttempt(us_socket_t *s) {
        auto it = clientAttempts.find(s);
        if (it == clientAttempts.end()) {
            return 0;
        }
        unsigned int id = it->second.id;
        clientAttempts.erase(it);
        return id;
    }

    struct RouterData {
        HttpResponse<SSL> *httpResponse;
        HttpRequest *httpRequest;
    };

    /* This is the currently browsed-to router when using SNI */
    HttpRouter<RouterData> *currentRouter = &router;

    /* This is the default router for default SNI or non-SSL */
    HttpRouter<RouterData> router;
    void *upgradedWebSocket = nullptr;
    char *reqRemaningData = nullptr;
    unsigned int reqRemaningDataLen = 0;
    bool isParsingHttp = false;

    /* If we are main acceptor, distribute to these apps */
    std::vector<void *> childApps;
    unsigned int roundRobin = 0;
};

}

#endif // UWS_HTTPCONTEXTDATA_H
