#ifndef SETTINGSWIDGET_H
#define SETTINGSWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

class SettingsWidget : public QWidget {
    Q_OBJECT

public:
    explicit SettingsWidget(QWidget *parent = nullptr);
    ~SettingsWidget();
    const QMap<QString, QString> getSettings();

signals:
    void settingsAccepted();

private slots:
    void onOkClicked();

private:
    QLabel *domainServerLabel;
    QLineEdit *domainServerLineEdit;
    QLabel *userLabel;
    QLineEdit *userLineEdit;
    QLabel *passwordLabel;
    QLineEdit *passwordLineEdit;

    QPushButton *okButton;

    QVBoxLayout *layout;
};

#endif // SETTINGSWIDGET_H
