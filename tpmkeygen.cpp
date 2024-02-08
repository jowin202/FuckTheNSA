#include "tpmkeygen.h"

TPMKeyGen::TPMKeyGen(QByteArray data)
{
    port.setPortName(settings.value("serial_tty").toString());



    QObject::connect(&port, &QIODevice::readyRead, [&]() {
        QByteArray data = port.readAll();
        result += data;
        qDebug() << result;
    });

    port.open(QIODevice::ReadWrite);
    port.setBaudRate(QSerialPort::Baud9600);
    port.setDataBits(QSerialPort::Data8);
    port.setParity(QSerialPort::NoParity);
    port.setStopBits(QSerialPort::OneStop);
    port.setFlowControl(QSerialPort::NoFlowControl);
    port.setDataTerminalReady(true);

    if (port.isOpen())
    {
        qDebug() << port.write(data);
    }
}
