#include "settingswidget.h"

SettingsWidget::SettingsWidget(QWidget *parent)
    : QWidget(parent)
    , domainServerLabel( new QLabel("Domain:", this))
    , domainServerLineEdit( new QLineEdit(this))
    , userLabel(new QLabel("User:", this))
    , userLineEdit(new QLineEdit(this))
    , passwordLabel(new QLabel("Password:", this))
    , passwordLineEdit(new QLineEdit(this))
    , okButton(new QPushButton("Save"))
    , layout(nullptr)
{
    passwordLineEdit->setEchoMode(QLineEdit::Password);

    layout = new QVBoxLayout(this);
    layout->addWidget(domainServerLabel);
    layout->addWidget(domainServerLineEdit);
    layout->addWidget(userLabel);
    layout->addWidget(userLineEdit);
    layout->addWidget(passwordLabel);
    layout->addWidget(passwordLineEdit);
    layout->addWidget(okButton);

    setLayout(layout);
    move(this->rect().center() - rect().center()); // Posiziona al centro di MainWindow
    setFixedSize(300, 200);
    connect(okButton, &QPushButton::clicked, this, &SettingsWidget::onOkClicked);

}

SettingsWidget::~SettingsWidget()
{
    delete userLabel;
    delete userLineEdit;
    delete passwordLabel;
    delete passwordLineEdit;
    delete layout;
}

const QMap<QString, QString> SettingsWidget::getSettings(){
    QMap<QString, QString> settings;
    settings.insert(domainServerLabel->text(), domainServerLineEdit->text());
    settings.insert(userLabel->text(), userLineEdit->text());
    settings.insert(passwordLabel->text(), passwordLineEdit->text());

    return settings;
}

void SettingsWidget::onOkClicked() {
    emit settingsAccepted();
}

