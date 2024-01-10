#ifndef CREATETAR_H
#define CREATETAR_H

#include <QThread>
#include <QObject>

#include <QDir>
#include <QFileInfoList>
#include <QDebug>

#include "microtar/src/microtar.h"

class CreateTar : public QThread
{
    Q_OBJECT
public:
    explicit CreateTar(QString dir, QObject *parent = nullptr);

    void processDirectory(QString abs_path, QString rel_path);
    void run();

private:
    QString dir;
    mtar_t tar;

    char buffer[1024];
    int len;
};

#endif // CREATETAR_H
