#ifndef OPTIONWINDOW_H
#define OPTIONWINDOW_H


//sudo apt-get install libqt6serialport6-dev
#include <QSerialPort>
#include <QSerialPortInfo>

#include <QWidget>
#include <QKeyEvent>
#include <QSettings>

namespace Ui {
class OptionWindow;
}

class OptionWindow : public QWidget
{
    Q_OBJECT

public:
    explicit OptionWindow(QWidget *parent = nullptr);
    ~OptionWindow();

    void keyPressEvent(QKeyEvent *e) {
        if(e->key() == Qt::Key_Escape)
            this->close();
        else if(e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter)
            this->on_button_ok_clicked();
    }

private slots:
    void on_button_ok_clicked();
    void on_button_cancel_clicked();

    void save_settings();

private:
    Ui::OptionWindow *ui;
    QSettings settings;
};

#endif // OPTIONWINDOW_H
