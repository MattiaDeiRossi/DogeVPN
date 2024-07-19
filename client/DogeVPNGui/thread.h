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
    const char *user_, *pwd_, *domain_, *port_;
};

#endif // THREAD_H
