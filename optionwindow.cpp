#include "optionwindow.h"
#include "ui_optionwindow.h"

OptionWindow::OptionWindow(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OptionWindow)
{
    ui->setupUi(this);

    for (int i = 0; i < QSerialPortInfo::availablePorts().length(); i++)
        this->ui->combo_serial->addItem(QSerialPortInfo::availablePorts().at(i).systemLocation());

}

OptionWindow::~OptionWindow()
{
    delete ui;
}

void OptionWindow::on_button_ok_clicked()
{
    this->save_settings();
    this->close();
}


void OptionWindow::on_button_cancel_clicked()
{
    this->close();
}

void OptionWindow::save_settings()
{
    settings.setValue("serial_tty", this->ui->combo_serial->currentText());
}

