#include "cipher.h"

Cipher::Cipher(QString file_from, QString file_to, QJsonArray ctx, bool encrypt) : QThread()
{
    this->file_from = file_from;
    this->file_to = file_to;
    if (encrypt)
        this->ctx = ctx;
    else
        this->ctx = this->invert_context(ctx);

    this->encrypt = encrypt;
}

void Cipher::run()
{
    using namespace CryptoPP;
    QFile f(this->file_from);
    size = f.size();

    CryptoPP::FileSource *file_source = new FileSource(this->file_from.toStdString().data(), false);

    CryptoPP::StreamTransformationFilter *previous_filter = 0;
    CryptoPP::StreamTransformationFilter *first_filter = 0;


    QByteArray iv;
    if (encrypt)
    {
        for (int i = 0; i < ctx.count(); i++)
        {
            QJsonArray current_cipher = ctx.at(i).toArray();
            QString cipher  = current_cipher.at(0).toString();
            QString mode    = current_cipher.at(1).toString();
            QString enc_dec = current_cipher.at(2).toString();
            QByteArray key  = QByteArray::fromHex(current_cipher.at(3).toString().toUtf8());

                size_t iv_size = 16; //16 byte block length
                if (cipher == "Threefish1024")
                    iv_size = 128; //1024 bit block len for threefish1024
                byte iv_tmp[128];
                CryptoPP::OS_GenerateRandomBlock(false,iv_tmp,iv_size);
                iv = QByteArray(reinterpret_cast<char*>(iv_tmp),iv_size);
                this->IVs.append(iv);
                current_cipher.append(QString(iv.toHex()));
                ctx.removeAt(i);
                ctx.insert(i,current_cipher);
        }
    }
    else
    {
        for (int i = ctx.count()-1; i >= 0; i--)
        {
            QJsonArray current_cipher = ctx.at(i).toArray();
            QString cipher  = current_cipher.at(0).toString();
            QString mode    = current_cipher.at(1).toString();
            QString enc_dec = current_cipher.at(2).toString();
            QByteArray key  = QByteArray::fromHex(current_cipher.at(3).toString().toUtf8());
            size_t iv_size = 16; //16 byte block length
            if (cipher == "Threefish1024")
                iv_size = 128; //1024 bit block len for threefish1024
            std::string iv_tmp;
            file_source->Attach(new StringSink(iv_tmp));
            file_source->Pump(iv_size);
            iv = QByteArray(iv_tmp.data(),iv_tmp.size());
            this->IVs.append(iv);
            current_cipher.append(QString(iv.toHex()));
            ctx.removeAt(i);
            ctx.insert(i,current_cipher);
        }
    }


    for (int i = 0; i < ctx.count(); i++)
    {
        QJsonArray current_cipher = ctx.at(i).toArray();
        QString cipher  = current_cipher.at(0).toString();
        QString mode    = current_cipher.at(1).toString();
        QString enc_dec = current_cipher.at(2).toString();
        QByteArray key  = QByteArray::fromHex(current_cipher.at(3).toString().toUtf8());
        QByteArray iv  = QByteArray::fromHex(current_cipher.at(4).toString().toUtf8());

        CryptoPP::StreamTransformationFilter *filter = 0;

        if (cipher == "CAST256" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<CAST256>::Encryption *e = new CBC_CTS_Mode< CAST256>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "CAST256" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<CAST256>::Decryption *d = new CBC_CTS_Mode< CAST256>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "MARS" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<MARS>::Encryption *e = new CBC_CTS_Mode< MARS>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "MARS" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<MARS>::Decryption *d = new CBC_CTS_Mode< MARS>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "AES" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<AES>::Encryption *e = new CBC_CTS_Mode< AES>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "AES" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<AES>::Decryption *d = new CBC_CTS_Mode< AES>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "RC6" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<RC6>::Encryption *e = new CBC_CTS_Mode< RC6>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "RC6" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<RC6>::Decryption *d = new CBC_CTS_Mode< RC6>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Serpent" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<Serpent>::Encryption *e = new CBC_CTS_Mode< Serpent>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Serpent" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<Serpent>::Decryption *d = new CBC_CTS_Mode< Serpent>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Threefish1024" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<Threefish1024>::Encryption *e = new CBC_CTS_Mode< Threefish1024>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Threefish1024" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<Threefish1024>::Decryption *d = new CBC_CTS_Mode< Threefish1024>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Twofish" && mode == "CBC_CTS" && enc_dec == "ENC")
        {
            CBC_CTS_Mode<Twofish>::Encryption *e = new CBC_CTS_Mode< Twofish>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Twofish" && mode == "CBC_CTS" && enc_dec == "DEC")
        {
            CBC_CTS_Mode<Twofish>::Decryption *d = new CBC_CTS_Mode< Twofish>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "CAST256" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<CAST256>::Encryption *e = new OFB_Mode< CAST256>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "CAST256" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<CAST256>::Decryption *d = new OFB_Mode< CAST256>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "MARS" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<MARS>::Encryption *e = new OFB_Mode< MARS>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "MARS" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<MARS>::Decryption *d = new OFB_Mode< MARS>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "AES" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<AES>::Encryption *e = new OFB_Mode< AES>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "AES" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<AES>::Decryption *d = new OFB_Mode< AES>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "RC6" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<RC6>::Encryption *e = new OFB_Mode< RC6>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "RC6" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<RC6>::Decryption *d = new OFB_Mode< RC6>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Serpent" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<Serpent>::Encryption *e = new OFB_Mode< Serpent>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Serpent" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<Serpent>::Decryption *d = new OFB_Mode< Serpent>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Threefish1024" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<Threefish1024>::Encryption *e = new OFB_Mode< Threefish1024>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Threefish1024" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<Threefish1024>::Decryption *d = new OFB_Mode< Threefish1024>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Twofish" && mode == "OFB" && enc_dec == "ENC")
        {
            OFB_Mode<Twofish>::Encryption *e = new OFB_Mode< Twofish>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Twofish" && mode == "OFB" && enc_dec == "DEC")
        {
            OFB_Mode<Twofish>::Decryption *d = new OFB_Mode< Twofish>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "CAST256" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<CAST256>::Encryption *e = new CTR_Mode< CAST256>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "CAST256" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<CAST256>::Decryption *d = new CTR_Mode< CAST256>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "MARS" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<MARS>::Encryption *e = new CTR_Mode< MARS>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "MARS" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<MARS>::Decryption *d = new CTR_Mode< MARS>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "AES" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<AES>::Encryption *e = new CTR_Mode< AES>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "AES" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<AES>::Decryption *d = new CTR_Mode< AES>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "RC6" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<RC6>::Encryption *e = new CTR_Mode< RC6>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "RC6" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<RC6>::Decryption *d = new CTR_Mode< RC6>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Serpent" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<Serpent>::Encryption *e = new CTR_Mode< Serpent>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Serpent" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<Serpent>::Decryption *d = new CTR_Mode< Serpent>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Threefish1024" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<Threefish1024>::Encryption *e = new CTR_Mode< Threefish1024>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Threefish1024" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<Threefish1024>::Decryption *d = new CTR_Mode< Threefish1024>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Twofish" && mode == "CTR" && enc_dec == "ENC")
        {
            CTR_Mode<Twofish>::Encryption *e = new CTR_Mode< Twofish>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Twofish" && mode == "CTR" && enc_dec == "DEC")
        {
            CTR_Mode<Twofish>::Decryption *d = new CTR_Mode< Twofish>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "CAST256" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<CAST256>::Encryption *e = new CFB_Mode< CAST256>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "CAST256" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<CAST256>::Decryption *d = new CFB_Mode< CAST256>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "MARS" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<MARS>::Encryption *e = new CFB_Mode< MARS>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "MARS" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<MARS>::Decryption *d = new CFB_Mode< MARS>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "AES" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<AES>::Encryption *e = new CFB_Mode< AES>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "AES" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<AES>::Decryption *d = new CFB_Mode< AES>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "RC6" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<RC6>::Encryption *e = new CFB_Mode< RC6>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "RC6" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<RC6>::Decryption *d = new CFB_Mode< RC6>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Serpent" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<Serpent>::Encryption *e = new CFB_Mode< Serpent>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Serpent" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<Serpent>::Decryption *d = new CFB_Mode< Serpent>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Threefish1024" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<Threefish1024>::Encryption *e = new CFB_Mode< Threefish1024>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Threefish1024" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<Threefish1024>::Decryption *d = new CFB_Mode< Threefish1024>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else if (cipher == "Twofish" && mode == "CFB" && enc_dec == "ENC")
        {
            CFB_Mode<Twofish>::Encryption *e = new CFB_Mode< Twofish>::Encryption();
            e->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*e);
        }
        else if (cipher == "Twofish" && mode == "CFB" && enc_dec == "DEC")
        {
            CFB_Mode<Twofish>::Decryption *d = new CFB_Mode< Twofish>::Decryption();
            d->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));
            filter = new StreamTransformationFilter(*d);
        }
        else
        {
            qDebug() << "should not happen";
        }


        if (i == 0)
            first_filter = filter;
        else
            previous_filter->Attach(filter);

        previous_filter = filter;
    }

    file_source->Attach(first_filter);
    CryptoPP::FileSink file_sink(this->file_to.toStdString().data());

    if (encrypt) //Attach IVs when encrypt
        StringSource(IVs.toStdString(),true, new Redirector(file_sink));

    if (previous_filter != 0)
    {
        MeterFilter meter = MeterFilter( new Redirector(file_sink) );
        previous_filter->Attach(new Redirector(meter));

        //while (!file_source->SourceExhausted())// && meter.GetTotalBytes() < (unsigned int)size)
        while(!file_source->GetStream()->eof())
        {
            file_source->Pump(65536);
            emit progress( qRound( meter.GetTotalBytes()/(1.0*size) * 100) );
        }
    }

}

QJsonArray Cipher::invert_context(QJsonArray ctx)
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

