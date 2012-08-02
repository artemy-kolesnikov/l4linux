/**
 * server.cc: L4re Server-side code
 *
 * (c) 2012 Artemy Kolesnikov <artemy.kolesnikov@gmail.com>
 */

#include <stdio.h>
#include <l4/re/env>
#include <l4/re/util/cap_alloc>
#include <l4/re/util/object_registry>
#include <l4/cxx/ipc_server>
#include <l4/re/dataspace>

#include "shared.h"

#include <string>
#include <vector>

#include <string.h>

#include <l4/crypto/aes.h>
#include <l4/crypto/cbc.h>

namespace {

const size_t DATASPACE_SIZE = 4096;
L4Re::Util::Registry_server<> server;

class SharedDataspace {
public:
    enum ErrorCode {
        E_OK,
        E_CAP_SLOT,
        E_MALLOC,
        E_ATTACH
    };

    static const char* errorString(ErrorCode code) {
        switch (code) {
            case E_OK:
                return "No error";
            case E_CAP_SLOT:
                return "Canot not get capability slot";
            case E_MALLOC:
                return "Memory allocation failed";
            case E_ATTACH:
                return "Canot attach dataspace";
            default:
                return "";
        }
    }

    SharedDataspace() : attachedAddr(0), inited(false) {}

    ~SharedDataspace() {
        L4Re::Env::env()->rm()->detach(attachedAddr, 0);
        L4Re::Util::cap_alloc.free(sharedDataspace);
    }

    ErrorCode init(size_t dataspaceSize) {
        sharedDataspace = L4Re::Util::cap_alloc.alloc<L4Re::Dataspace>();
        if (!sharedDataspace.is_valid()) {
            return E_CAP_SLOT;
        }

        int err =  L4Re::Env::env()->mem_alloc()->alloc(dataspaceSize, sharedDataspace, 0);
        if (err < 0) {
            L4Re::Util::cap_alloc.free(sharedDataspace);
            return E_MALLOC;
        }

        /*
        * Attach DS to local address space
        */
        err =  L4Re::Env::env()->rm()->attach(&attachedAddr, sharedDataspace->size(),
                            L4Re::Rm::Search_addr,
                            sharedDataspace);
        if (err < 0) {
            L4Re::Util::cap_alloc.free(sharedDataspace);
            return E_ATTACH;
        }

        return E_OK;
    }

    L4::Cap<L4Re::Dataspace> getDataspace() const {
        return sharedDataspace;
    }

    char* getAttachedAddress() const {
        return attachedAddr;
    }

private:
    SharedDataspace(const SharedDataspace&);
    SharedDataspace& operator=(const SharedDataspace&);

private:
    L4::Cap<L4Re::Dataspace> sharedDataspace;
    char* attachedAddr;
    bool inited;
};

class CryptServer : public L4::Server_object {
public:
    explicit CryptServer(SharedDataspace& sharedDs) : sharedDataspace(sharedDs) {}

    int dispatch(l4_umword_t obj, L4::Ipc::Iostream &ios);

    static void encrypt(char* /*buf*/, size_t /*size*/) {
    }

    static void decrypt(char* /*buf*/, size_t /*size*/) {
    }

private:
    SharedDataspace& sharedDataspace;
};

int CryptServer::dispatch(l4_umword_t, L4::Ipc::Iostream &ios) {
    int result = L4_EOK;

    l4_msgtag_t t;
    ios >> t;

    size_t size;
    ios >> size;

    switch (t.label())
    {
    case Protocol::Encrypt:
        CryptServer::encrypt(sharedDataspace.getAttachedAddress(), size);
        break;
    case Protocol::Decrypt:
        CryptServer::decrypt(sharedDataspace.getAttachedAddress(), size);
        break;
    case Protocol::GetDataspace:
        ios << sharedDataspace.getDataspace();
        break;
    default:
        result = -L4_EBADPROTO;
    }

    return result;
}

}

int main() {
    SharedDataspace sharedDataspace;
    SharedDataspace::ErrorCode err = sharedDataspace.init(DATASPACE_SIZE);
    if (err != SharedDataspace::E_OK) {
        printf("Error while create shared dataspace: %s", SharedDataspace::errorString(err));
        return 1;
    }

    static CryptServer cryptServer(sharedDataspace);

    // Register calculation server
    if (!server.registry()->register_obj(&cryptServer, "crypt_server").is_valid()) {
        printf("Could not register my service, readonly namespace?");
        return 1;
    }

    // Wait for client requests
    server.loop();
    return 0;
}
