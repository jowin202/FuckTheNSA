#include "createtar.h"


CreateTar::CreateTar(QString dir, QObject *parent)
    : QThread{parent}
{
    this->dir = dir;
    if (this->dir.endsWith(QDir::separator()))
        this->dir.chop(1);
}

void CreateTar::processDirectory(QString abs_path, QString rel_path) {
    QDir directory(abs_path + QDir::separator() + rel_path);
    mtar_write_dir_header(&tar, rel_path.replace(QDir::separator(),"/").toStdString().data());

    QFileInfoList entries = directory.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
    foreach (const QFileInfo &entry, entries) {
        if (entry.isDir()) {
            processDirectory(abs_path, rel_path + entry.fileName() + QDir::separator());
        } else if (entry.isFile()) {
            QString rel_file_path = rel_path + entry.fileName();
            QFile f(abs_path + QDir::separator() + rel_file_path);
            f.open(QIODevice::ReadOnly);
            mtar_write_file_header(&tar, rel_file_path.replace(QDir::separator(),"/").toStdString().data(), f.size());
            while (!f.atEnd())
            {
                len = f.read(buffer, 1024);
                mtar_write_data(&tar, buffer, len);
            }
            f.close();
        }
    }
}

void CreateTar::run()
{
    mtar_open(&tar, "test.tar", "w");
    this->processDirectory(dir, "");
    mtar_finalize(&tar);
    mtar_close(&tar);

    //::sleep(5);
    //qDebug() << "finished";
}
