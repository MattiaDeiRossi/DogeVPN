#ifndef THREAD_H
#define THREAD_H

#include <QThread>

class Thread : public QThread
{
    Q_OBJECT

public:
    Thread(QObject *parent = nullptr);
    ~Thread();

    void setParams(const char *user, const char *pwd);

signals:
    void threadFinished(int result);

protected:
    void run() override;

private:
    const char *m_user;
    const char *m_pwd;
};

#endif // THREAD_H
