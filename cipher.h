#ifndef CIPHER_H
#define CIPHER_H

#include <QThread>
#include <QByteArray>

#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>

#include <iostream>

#include "cryptopp/osrng.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/aes.h"
#include "cryptopp/rc6.h"
#include "cryptopp/mars.h"
#include "cryptopp/twofish.h"
#include "cryptopp/serpent.h"
#include "cryptopp/cast.h"
#include "cryptopp/threefish.h"
#include "cryptopp/modes.h"

#include <QRandomGenerator64>
#include <QFile>
using namespace CryptoPP;


class Cipher : public QThread
{
    Q_OBJECT

public:
    Cipher(QString file_from, QString file_to, QJsonArray ctx, bool encrypt);
    void run();

    QJsonArray invert_context(QJsonArray ctx);

signals:
    void progress(int);


private:
    QString file_from;
    QString file_to;
    QJsonArray ctx;
    QByteArray IVs;
    qint64 size;
    bool encrypt;
};

#endif // CIPHER_H
