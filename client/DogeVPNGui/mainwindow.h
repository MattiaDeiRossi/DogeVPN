#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "settingswidget.h"
#include "thread.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_connectButton_clicked();

    void on_actionNew_triggered();

    void handleSettingsAccepted();

    void on_disconnectButton_clicked();

    void on_actionOpen_triggered();

    void handleThreadFinished(int result);

private:
    Ui::MainWindow *ui;
    Thread *client_thread_;
    SettingsWidget *settingsWidget;
    QMap<QString, QString> settings_;

};
#endif // MAINWINDOW_H
