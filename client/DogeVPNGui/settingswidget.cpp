#include "settingswidget.h"

SettingsWidget::SettingsWidget(QWidget *parent)
    : QDialog(parent)
    , domainServerLabel( new QLabel("Domain", this))
    , domainServerLineEdit( new QLineEdit(this))
    , portServerLabel( new QLabel("Port", this))
    , portServerLineEdit( new QLineEdit(this))
    , userLabel(new QLabel("Username", this))
    , userLineEdit(new QLineEdit(this))
    , passwordLabel(new QLabel("Password", this))
    , passwordLineEdit(new QLineEdit(this))
    , saveButton(new QPushButton("Save"))
    , okButton(new QPushButton("Ok"))
    , togglePswButton(new QPushButton("Show"))
    , layout(nullptr)
{
    passwordLineEdit->setEchoMode(QLineEdit::Password);

    layout = new QVBoxLayout(this);
    QHBoxLayout *domainLabelLayout = new QHBoxLayout;
    domainLabelLayout->addWidget(domainServerLabel);
    domainLabelLayout->addWidget(portServerLabel);
    layout->addLayout(domainLabelLayout);

    QHBoxLayout *domainLayout = new QHBoxLayout;
    domainLayout->addWidget(domainServerLineEdit);
    domainLayout->addWidget(portServerLineEdit);
    layout->addLayout(domainLayout);

    layout->addWidget(userLabel);
    layout->addWidget(userLineEdit);
    layout->addWidget(passwordLabel);

    QHBoxLayout *passwordLayout = new QHBoxLayout;
    passwordLayout->addWidget(passwordLineEdit);
    passwordLayout->addWidget(togglePswButton);
    layout->addLayout(passwordLayout);

    QHBoxLayout *buttonLayout = new QHBoxLayout;
    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(saveButton);
    layout->addLayout(buttonLayout);

    setLayout(layout);
    move(this->rect().center() - rect().center());
    setFixedSize(300, 200);

    connect(okButton, &QPushButton::clicked, this, &SettingsWidget::onOkClicked);
    connect(saveButton, &QPushButton::clicked, this, &SettingsWidget::onSaveClicked);
    connect(togglePswButton, &QPushButton::clicked, this, &SettingsWidget::togglePasswordVisibility);
    connect(this, &SettingsWidget::refreshSettings, this, &SettingsWidget::fillFields);
}

SettingsWidget::~SettingsWidget()
{
    delete userLabel;
    delete userLineEdit;
    delete passwordLabel;
    delete passwordLineEdit;
    delete okButton;
    delete saveButton;
    delete togglePswButton;
    delete layout;
}

void SettingsWidget::togglePasswordVisibility() {
    if (passwordLineEdit->echoMode() == QLineEdit::Password) {
        passwordLineEdit->setEchoMode(QLineEdit::Normal);
        togglePswButton->setText("Hide");
    } else {
        passwordLineEdit->setEchoMode(QLineEdit::Password);
        togglePswButton->setText("Show");
    }
}

QString SettingsWidget::loadFromFile(){
    QString fileName = QFileDialog::getOpenFileName(this, tr("Apri file di testo"), "/DogeVPN", tr("File di testo (*.txt);;Tutti i file (*.*)"));

    if (fileName.isEmpty())
        return "";

    QFile file(fileName);

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Unable to open the file: ") + file.errorString());
        return "";
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
    return fileName;
}

void SettingsWidget::setSettings(){
    settings_.insert(domainServerLabel->text().toLower(), domainServerLineEdit->text());
    settings_.insert(portServerLabel->text().toLower(), portServerLineEdit->text());
    settings_.insert(userLabel->text().toLower(), userLineEdit->text());
    settings_.insert(passwordLabel->text().toLower(), passwordLineEdit->text());
}
const QMap<QString, QString> SettingsWidget::getSettings() const {
    return settings_;
}

void SettingsWidget::fillFields(){
    if(!settings_.empty()){
        domainServerLineEdit->setText(settings_.value("domain"));
        portServerLineEdit->setText(settings_.value("port"));
        userLineEdit->setText(settings_.value("username"));
        passwordLineEdit->setText(settings_.value("password"));
    }
}

void SettingsWidget::onOkClicked() {
    setSettings();
    for (auto it = settings_.constBegin(); it != settings_.constEnd(); ++it) {
        qDebug("%s: %s",it.key().toStdString().c_str(), it.value().toStdString().c_str());
    }
    emit settingsAccepted();
}

void SettingsWidget::onSaveClicked(){
    QString fileName = QFileDialog::getOpenFileName(this, tr("Save text file"), "/DogeVPN", tr("Text files (*.txt);;All files (*.*)"));

    if (fileName.isEmpty())
        return;

    QFile file(fileName);

    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Error"), tr("Unable to save the file: ") + file.errorString());
        return;
    }

    QTextStream out(&file);

    setSettings();
    out << "domain: " << settings_.value("domain") << "\n";
    out << "port: " << settings_.value("port") << "\n";
    out << "username: " << settings_.value("username") << "\n";
    out << "password: " << settings_.value("password") << "\n";

    file.close();

    QMessageBox::information(this, tr("Save completed"), tr("Settings have been saved successfully."));
}
