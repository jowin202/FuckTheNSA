#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "cipher.h"
#include "optionwindow.h"
#include "createtar.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QJsonArray cipher4;
    cipher4 << "AES" << "CFB" << "ENC" << "4f2b891553364043c8c9600d2e26c915600f317380d3db0efb0635bc5e7f019f";
    QJsonArray cipher3;
    cipher3 << "Threefish1024" << "CFB" << "ENC" << "ccd08774ff463468b9b0c14dcc0ee6f3eacb53dc686700b69ca35c44964fe3477b8199b4b40062f6b3891d6ba3ae37d05e0c5e9d1335a5c254e504acc5fbc6e30d24c9e280b2c9169bb44c1abb05d1f7746dd9279de4d82919913ed44908802b9e108325767b2656aa52897311994aebbba8e54685c78c495f2b84bdbc332afa";
    QJsonArray cipher2;
    cipher2 << "Twofish" << "CTR" << "ENC" << "520b07ac691e002f3323e521f3fedd125e3d6e0bcf277db93edbc424874ac78e";
    QJsonArray cipher1;
    cipher1 << "Serpent" << "OFB" << "ENC" << "6d75cb3cb688a091aeae77b1a09524c951ce2391dccbeda2164de3b321c62146";
    cipher_ctx << cipher1 << cipher2 << cipher3 << cipher4;
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::dropEvent(QDropEvent *event)
{
    const QMimeData* mimeData = event->mimeData();
    if (mimeData->hasUrls() && mimeData->urls().length() == 1)
    {
        QString file_path = mimeData->urls().at(0).toLocalFile();
        QFileInfo f(file_path);
        if (f.isDir())
        {
            CreateTar *createtar = new CreateTar(file_path);
            connect(createtar, &CreateTar::finished, this, [=](){ this->setEnabled(true); });
            createtar->start();
            this->setEnabled(false);

        }
        else
            this->ui->line_file_in->setText(file_path);
    }
}

void MainWindow::updateOutputFile()
{
    if (this->ui->check_update_output->isChecked())
    {
        this->ui->line_file_out->setText(this->ui->line_file_in->text() + ".fnsa");
    }
}


void MainWindow::on_button_encrypt_clicked()
{
    Cipher *c = new Cipher(this->ui->line_file_in->text(), this->ui->line_file_out->text(), cipher_ctx, true);
    connect(c,SIGNAL(progress(int)), this, SLOT(update_gui(int)));
    c->start();
}


void MainWindow::on_button_decrypt_clicked()
{
    Cipher *c = new Cipher(this->ui->line_file_out->text(), this->ui->line_file_in->text() + "_new", this->cipher_ctx, false);
    connect(c,SIGNAL(progress(int)), this, SLOT(update_gui(int)));
    c->start();
}

void MainWindow::update_gui(int percent)
{
    this->ui->progressBar->setValue(percent);
}


void MainWindow::on_actionOptions_triggered()
{
    OptionWindow *options = new OptionWindow;
    options->show();
}

