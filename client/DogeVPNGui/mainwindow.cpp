#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "client.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>

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
    auto us = settings_.value("user").toStdString().c_str();
    auto psw = settings_.value("password").toStdString().c_str();
    std::cout<< us << " ****** "<< psw << std::endl;


    qDebug("Connecting");
    if(!client_thread_){
        client_thread_ = new Thread(this);
    }

    client_thread_->setParams(us, psw);
    client_thread_->start();
    ui->connectionStatus->setText("Connected");
    ui->connectionStatus->setStyleSheet("color: green;");
}

void MainWindow::on_disconnectButton_clicked()
{

    if (client_thread_->isRunning()) {
        client_thread_->terminate();
        client_thread_->wait();
    }
    ui->connectionStatus->setText("Disconnected");
    ui->connectionStatus->setStyleSheet("color: red;");
    qDebug("Disconnecting");
}

void MainWindow::handleThreadFinished(int result)
{
    ui->connectionStatus->setText("Disconnected");
    ui->connectionStatus->setStyleSheet("color: red;");
    std::cout << result << std::endl;
}

void MainWindow::on_actionOpen_triggered()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Apri file di testo"), "", tr("File di testo (*.txt);;Tutti i file (*.*)"));

    if (fileName.isEmpty())
        return;

    QFile file(fileName);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Errore"), tr("Impossibile aprire il file: ") + file.errorString());
        return;
    }

    QTextStream in(&file);

    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();

        if (line.isEmpty() || line.startsWith('#'))
            continue;

        QStringList parts = line.split(':');

        if (parts.size() == 2) {
            QString key = parts[0].trimmed();
            QString value = parts[1].trimmed();
            settings_[key] = value;
        }
    }

    file.close();
    for (auto it = settings_.constBegin(); it != settings_.constEnd(); ++it) {
        qDebug("%s: %s",it.key().toStdString().c_str(), it.value().toStdString().c_str());
    }

}

void MainWindow::on_actionNew_triggered()
{
    if (settingsWidget) {
        settingsWidget->show();
    }

}

void MainWindow::handleSettingsAccepted() {
    settings_ = settingsWidget->getSettings();
    qDebug("received");
    settingsWidget->hide();
    this->show();
    // Salva le informazioni ricevute
    // savedUser = settings.value("user");
    // savedPassword = settings.value("password");
}
