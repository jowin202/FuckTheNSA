#include "tpmkeygen.h"

TPMKeyGen::TPMKeyGen(QByteArray data)
{
    port.setPortName(settings.value("serial_tty").toString());



    QObject::connect(&port, &QIODevice::readyRead, [&]() {
        QByteArray data = port.readAll();
        result += data;

        QList<QByteArray> tokens = result.split('\n');
        if (tokens.contains("in 1") && tokens.contains("in 255") && tokens.count() == 257)
        {
            QByteArray key = QByteArray::fromHex(tokens.at(255));
            emit key_generation_finished(key);
        }

    });

    port.open(QIODevice::ReadWrite);
    if (port.isOpen())
    {
        port.setBaudRate(QSerialPort::Baud9600);
        port.setDataBits(QSerialPort::Data8);
        port.setParity(QSerialPort::NoParity);
        port.setStopBits(QSerialPort::OneStop);
        port.setFlowControl(QSerialPort::NoFlowControl);
        port.setDataTerminalReady(true);

        qDebug() << port.write(data);
    }
}
