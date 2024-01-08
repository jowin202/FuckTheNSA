#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>

#include <QDebug>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


    QJsonArray invert_context(QJsonArray ctx);


private slots:
    void on_button_encrypt_clicked();
    void on_button_decrypt_clicked();
    void update_gui(int percent);

private:
    Ui::MainWindow *ui;

    QJsonArray cipher_ctx;
};
#endif // MAINWINDOW_H
