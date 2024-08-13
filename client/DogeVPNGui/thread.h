#ifndef THREAD_H
#define THREAD_H

#include <QThread>

class Thread : public QThread
{
    Q_OBJECT

public:
    Thread(QObject *parent = nullptr);
    ~Thread();

    void setParams(const char *domain, const char *port, const char *user, const char *pwd);

signals:
    void threadFinished(int result);

protected:
    void run() override;

private:
    char user_[256];
    char pwd_[256];
    char domain_[256];
    char port_[256];
};

#endif // THREAD_H
