#include "thread.h"
#include "client.h"
Thread::Thread(QObject *parent)
    : QThread(parent), m_user(nullptr), m_pwd(nullptr)
{
}

Thread::~Thread()
{
    if (isRunning()) {
        terminate();
        wait();
    }
}

void Thread::setParams(const char *user, const char *pwd)
{
    m_user = user;
    m_pwd = pwd;

}

void Thread::run()
{
    if (m_user && m_pwd) {
        int result = start_doge_vpn("Mattia", "1234567890mattia1234567890");
        emit threadFinished(result);
    } else {
        std::cerr << "Errore: Parametri non impostati correttamente" << std::endl;
    }
}
