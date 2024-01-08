modes = { "CBC_CTS", "CFB", "OFB", "CTR" }
algorithms = { "AES", "Serpent", "Twofish", "MARS", "RC6", "CAST256", "Threefish1024" }


count = 0
for mode in modes:
    for algorithm in algorithms:

        if count == 0:
            else_var = ""
        else:
            else_var = "else "
        count += 1

        print("\t\t" + else_var + "if (cipher == \"" + algorithm + "\" && mode == \"" + mode + "\" && enc_dec == \"ENC\")")
        print("\t\t{")
        print("\t\t\t" + mode + "_Mode<" + algorithm + ">::Encryption *e = new " + mode + "_Mode< " + algorithm + ">::Encryption();")
        print("\t\t\te->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));")
        print("\t\t\tfilter = new StreamTransformationFilter(*e);")
        print("\t\t}")
        print("\t\telse if (cipher == \"" + algorithm + "\" && mode == \"" + mode + "\" && enc_dec == \"DEC\")")
        print("\t\t{")
        print("\t\t\t" + mode + "_Mode<" + algorithm + ">::Decryption *d = new " + mode + "_Mode< " + algorithm + ">::Decryption();")
        print("\t\t\td->SetKeyWithIV((const byte*)(key.data()), key.length(), (const byte*)(iv.data()));")
        print("\t\t\tfilter = new StreamTransformationFilter(*d);")
        print("\t\t}")
