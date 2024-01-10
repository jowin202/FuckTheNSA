#include "optionwindow.h"
#include "ui_optionwindow.h"

OptionWindow::OptionWindow(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OptionWindow)
{
    ui->setupUi(this);
}

OptionWindow::~OptionWindow()
{
    delete ui;
}

void OptionWindow::on_button_ok_clicked()
{
    this->close();
}


void OptionWindow::on_button_cancel_clicked()
{
    this->close();
}

