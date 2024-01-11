#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>

#include <QSettings>

#include <QTemporaryFile>
#include <QFileInfo>
#include <QProcess>
#include <QMimeData>
#include <QDragEnterEvent>
#include <QProgressDialog>

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




public slots:
    void dragEnterEvent(QDragEnterEvent *event) {
            event->acceptProposedAction();
    }
    void dropEvent(QDropEvent *event);
    void updateOutputFile();

private slots:
    void on_button_encrypt_clicked();
    void on_button_decrypt_clicked();
    void update_gui(int percent);

    void on_actionOptions_triggered();

private:
    Ui::MainWindow *ui;

    QSettings settings;
    QJsonArray cipher_ctx;
};
#endif // MAINWINDOW_H
