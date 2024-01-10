#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "cipher.h"
#include "optionwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QJsonArray cipher4;
    cipher4 << "AES" << "CFB" << "ENC" << "4f2b891553364043c8c9600d2e26c915600f317380d3db0efb0635bc5e7f019f" << "aca3eb3419e11f1704a63b3a94e37d302eb210721f9874f165a297eed0620c41";
    QJsonArray cipher3;
    cipher3 << "Threefish1024" << "CFB" << "ENC" << "ccd08774ff463468b9b0c14dcc0ee6f3eacb53dc686700b69ca35c44964fe3477b8199b4b40062f6b3891d6ba3ae37d05e0c5e9d1335a5c254e504acc5fbc6e30d24c9e280b2c9169bb44c1abb05d1f7746dd9279de4d82919913ed44908802b9e108325767b2656aa52897311994aebbba8e54685c78c495f2b84bdbc332afa" << "be0d1e174addd05fb1c6b01e6706ea393c294487d5be8ec3448ca4276c98bd64c9fd7e149198e6ea64928f1502a2df4693565fac1b369f53da4d27cedc9244aad2e11921bf00e7a91d7afc8c77ff1d133157170cc7e68e6059f9f8fdfbba16c3ebe1e2e32e6c538fd7b661fc4f801274a28ffd0fde193049f155c7833e9c7f34";
    QJsonArray cipher2;
    cipher2 << "Twofish" << "CTR" << "ENC" << "520b07ac691e002f3323e521f3fedd125e3d6e0bcf277db93edbc424874ac78e" << "0ee902fbb74c1e961e47576bca7e8d5707cb63728a260a280e8abfb190b942cf";
    QJsonArray cipher1;
    cipher1 << "Serpent" << "OFB" << "ENC" << "6d75cb3cb688a091aeae77b1a09524c951ce2391dccbeda2164de3b321c62146" << "875c1cecd99c6e138e38589c42d29130dd40759c67e2284591dba6d2ea42b559";
    cipher_ctx << cipher1 << cipher2 << cipher3 << cipher4;
}

MainWindow::~MainWindow()
{
    delete ui;
}

QJsonArray MainWindow::invert_context(QJsonArray ctx)
{
    QJsonArray ctx2;
    for (int i = 0; i < ctx.count(); i++)
    {
        QJsonArray cipher = ctx.at(i).toArray();
        if (cipher.at(2).toString() == "ENC")
        {
            cipher.removeAt(2);
            cipher.insert(2,"DEC");
        }
        else if (cipher.at(2).toString() == "DEC")
        {
            cipher.removeAt(2);
            cipher.insert(2,"ENC");
        }
        ctx2.prepend(cipher);
    }
    return ctx2;
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

        }
        else
            this->ui->line_file_in->setText(file_path);
    }
}


void MainWindow::on_button_encrypt_clicked()
{
    Cipher *c = new Cipher(this->ui->line_file_in->text(), this->ui->line_file_out->text(), cipher_ctx);
    connect(c,SIGNAL(progress(int)), this, SLOT(update_gui(int)));
    c->start();
}


void MainWindow::on_button_decrypt_clicked()
{
    QJsonArray inverted_ctx = this->invert_context(this->cipher_ctx);

    Cipher *c = new Cipher(this->ui->line_file_out->text(), this->ui->line_file_in->text() + "_new", inverted_ctx);
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

