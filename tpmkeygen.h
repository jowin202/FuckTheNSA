#ifndef TPMKEYGEN_H
#define TPMKEYGEN_H


//sudo apt-get install libqt6serialport6-dev
#include <QSerialPort>
#include <QSerialPortInfo>
#include <QSettings>
#include <QDebug>

#include <QObject>

class TPMKeyGen : public QObject
{
    Q_OBJECT

public:
    TPMKeyGen(QByteArray data);


private:
    QSerialPort port;
    QSettings settings;
    QByteArray result;
};

#endif // TPMKEYGEN_H
