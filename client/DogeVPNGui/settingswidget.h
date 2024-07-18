#ifndef SETTINGSWIDGET_H
#define SETTINGSWIDGET_H

#include <QDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>

class SettingsWidget : public QDialog {
    Q_OBJECT

public:
    explicit SettingsWidget(QWidget *parent = nullptr);
    ~SettingsWidget();
    void setSettings();
    const QMap<QString, QString> getSettings() const;
    QString loadFromFile();
    void saveToFile();

signals:
    void settingsAccepted();
    void refreshSettings();

private slots:
    void togglePasswordVisibility();
    void fillFields();
    void onOkClicked();
    void onSaveClicked();

private:
    QLabel *domainServerLabel, *userLabel, *passwordLabel, *portServerLabel;
    QLineEdit *domainServerLineEdit, *portServerLineEdit, *userLineEdit, *passwordLineEdit;
    QPushButton *okButton, *saveButton, *togglePswButton;
    QVBoxLayout *layout;

    QMap<QString, QString> settings_;
};

#endif // SETTINGSWIDGET_H
