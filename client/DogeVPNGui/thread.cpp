#include "thread.h"
#include "client.h"
Thread::Thread(QObject *parent)
    : QThread(parent), user_(nullptr), pwd_(nullptr)
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
    domain_ = domain;
    port_ = port;
    user_ = user;
    pwd_ = pwd;

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
