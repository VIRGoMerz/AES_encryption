#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include "osrng.h"
#include "modes.h"
#include "base64.h"
#include "cryptlib.h"
#include "aes.h"
#include "filters.h"
 
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
using CryptoPP::Exception;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;
using namespace std;

#define byte char 
 
// 使用AES(CBC模式)加密，返回base64编码的数据
string encrytByAES(const string &plain, const string &key, const string &iv) {
    string cipher;
    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)iv.c_str());
 
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(plain, true, 
            new StreamTransformationFilter(e,
                new StringSink(cipher)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
    }
#if 0
    // Pretty print
    string encoded;
    StringSource(cipher, true,
        new Base64Encoder(
            new StringSink(encoded)
        ) // HexEncoder
    ); // StringSource
#endif
    return cipher;
}
 
// 使用AES(CBC模式)解密，encode为base64编码的密文
string decrytByAES(const string &encode, const string &key, const string &iv) {
#if 0
    string encodeByte;
    StringSource(encode, true, new Base64Decoder(
            new StringSink(encodeByte)
        ));
#endif
    string recovered;
    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)iv.c_str());
 
        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource s(encode, true, 
            new StreamTransformationFilter(d,
                new StringSink(recovered)
            ) // StreamTransformationFilter
        ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
    }
 
    return recovered;
}

int main()
{
    cout << "---------------" << endl
         << "Start AES test:" << endl;

    string key = "keynb12345678912";
    string iv = "ivnb123456789123";
    cout << "encryption key: " << key << endl;
    cout << "Initialization Vector: " << iv << endl;

    //读模型文件
    char* file_buffer;
    std::ifstream model;
    cout << "open model file" << endl;
    model.open("../data/PlainText", std::ios::binary);
    unsigned long src_file_size = 0;
    if (model.is_open())
    {
        std::streampos pos = model.tellg(); //save current position
        model.seekg(0, std::ios::end);
        src_file_size = model.tellg();
        cout << src_file_size << endl;
        model.seekg(pos); //restore saved position
        file_buffer = new char[src_file_size];
        model.read(file_buffer, src_file_size );
        model.close();
        cout << "read model file success" <<endl;
    }
    else
    {
        cout << "can not read file" <<endl;
        return -1;
    }

    //写入明文
    string plain;
    for(unsigned long len = 0; len < src_file_size; len++)
    {
        plain.push_back(file_buffer[len]);
    }
    cout << "plain length: " << plain.length() << endl;
    cout << "plain Text: " << endl << plain << endl;
    delete[] file_buffer;

    //加密
    string encoded = encrytByAES(plain, key, iv);
    cout << "cifer length: " << encoded.length() << endl;
    //写成加密文件
    std::ofstream encoded_model;
    encoded_model.open("../data/EncodedText", std::ios::out | std::ios::binary);
    encoded_model << encoded;
    encoded_model.close();

    char* model_buffer;
    std::ifstream decryt_model;
    cout << "open decryt model file" << endl;
    decryt_model.open("../data/EncodedText", std::ios::in | std::ios::binary);
    unsigned long dst_file_size;
    if (decryt_model.is_open())
    {
        std::streampos pos = decryt_model.tellg(); //save current position
        decryt_model.seekg(0, std::ios::end);
        dst_file_size = decryt_model.tellg();
        decryt_model.seekg(pos); //restore saved position
        model_buffer = new char[dst_file_size];
        decryt_model.read(model_buffer, dst_file_size);
        decryt_model.close();
    }
    else
    {
        cout << "can not read file" <<endl;
        return -1;
    }

    string _encoded;
    for(unsigned long len = 0; len < dst_file_size; len++)
    {
        _encoded.push_back(model_buffer[len]);
    }

    string recovered = decrytByAES(_encoded, key, iv);
    cout << "recover length: " << recovered.length() << endl;
    cout << "recover text: " << recovered << endl;
    delete[] model_buffer;

    return 0;
}
 
