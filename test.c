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
