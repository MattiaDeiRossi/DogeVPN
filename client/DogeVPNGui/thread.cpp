#include <iostream>
#include "thread.h"
#include "client.h"

Thread::Thread(QObject *parent)
    : QThread(parent)
{
}

Thread::~Thread()
{
    if (isRunning()) {
        terminate();
        wait();
    }
}

void Thread::setParams(const char *domain, const char *port, const char *user, const char *pwd)
{
    size_t bytes = 256;
    size_t max_bytes = 255;

    bzero(domain_, bytes);
    bzero(port_, bytes);
    bzero(user_, bytes);
    bzero(pwd_, bytes);

    strncpy(domain_, domain, max_bytes);
    strncpy(port_, port, max_bytes);
    strncpy(user_, user, max_bytes);
    strncpy(pwd_, pwd, max_bytes);
}

void Thread::run()
{
    if (user_ && pwd_ && domain_ && port_) {
        int result = start_doge_vpn(domain_, port_,user_, pwd_);
        emit threadFinished(result);
    } else {
        std::cerr << "Errore: Parametri non impostati correttamente" << std::endl;
    }
}
