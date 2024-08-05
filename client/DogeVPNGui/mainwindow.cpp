#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , settingsWidget(new SettingsWidget(this))
    , client_thread_(new Thread(this))
{
    ui->setupUi(this);
    setWindowTitle("DogeVPN Client");
    ui->connectionStatus->setText("Disconnected");
    ui->connectionStatus->setStyleSheet("color: red;");
    settingsWidget->hide();

    connect(settingsWidget, &SettingsWidget::settingsAccepted, this, &MainWindow::handleSettingsAccepted);
    connect(client_thread_, &Thread::threadFinished, this, &MainWindow::handleThreadFinished);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_connectButton_clicked()
{
    auto settings = settingsWidget->getSettings();
    for (auto it = settings.constBegin(); it != settings.constEnd(); ++it) {
        qDebug("%s: %s",it.key().toStdString().c_str(), it.value().toStdString().c_str());
    }

    if(settings.empty()){
        QMessageBox::warning(this, tr("Error"), tr("Settings are empty"));
        return;
    }

    auto domain = settings.value("domain").toStdString().c_str();
    auto port = settings.value("port").toStdString().c_str();
    auto us = settings.value("username").toStdString().c_str();
    auto psw = settings.value("password").toStdString().c_str();
    std::cout<< "Sending: "<< us << " "<< psw <<std::endl;

    if(!client_thread_){
        client_thread_ = new Thread(this);
    }

    client_thread_->setParams(domain, port, us, psw);
    client_thread_->start();
    ui->connectionStatus->setText("Connected");
    ui->connectionStatus->setStyleSheet("color: green;");
}

void MainWindow::on_disconnectButton_clicked()
{
    if (client_thread_->isRunning()) {
        client_thread_->terminate();
        client_thread_->wait();
    }else{
        QMessageBox::warning(this, tr("Error"), tr("Client is not connected"));
        return;
    }
    ui->connectionStatus->setText("Disconnected");
    ui->connectionStatus->setStyleSheet("color: red;");
}

void MainWindow::handleThreadFinished(int result)
{
    ui->connectionStatus->setText("Disconnected");
    ui->connectionStatus->setStyleSheet("color: red;");
    if(result<0)
        QMessageBox::warning(this, tr("Error"), tr("Connection closed woth an error"));

    std::cout << result << std::endl;
}

void MainWindow::on_actionOpen_triggered()
{
    auto fileName = settingsWidget->loadFromFile();
    if(fileName.isEmpty())
        QMessageBox::warning(this, tr("Error"), tr("FileName is empty"));

    if (settingsWidget) {
        settingsWidget->show();
        emit settingsWidget->refreshSettings();
    }
}

void MainWindow::on_actionNew_triggered()
{
    if (settingsWidget) {
        settingsWidget->show();
    }

}

void MainWindow::on_actionEdit_triggered()
{
    if (settingsWidget && !settingsWidget->getSettings().empty()) {
        settingsWidget->show();
        emit settingsWidget->refreshSettings();
    }
}


void MainWindow::handleSettingsAccepted() {
    auto settings = settingsWidget->getSettings();
    auto domain = settings.value("domain").toStdString();
    auto port= settings.value("port").toStdString();
    auto dp = domain + ":" + port;
    auto us = settings.value("username").toStdString().c_str();

    ui->domain_label->setText(dp.c_str());
    ui->name_label->setText(us);

    settingsWidget->close();

}



void MainWindow::on_actionInfo_triggered()
{
    QUrl url("https://github.com/MattiaDeiRossi/DogeVPN");
    QDesktopServices::openUrl(url);
}

