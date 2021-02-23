/*
    MIT License

    Copyright (c) 2021 m0dB https://github.com/m0dB

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include "sha256.h"
#include <cassert>
#include "urbytesdecoder.h"
#include <cstring>

using std::string;
using bytestring = std::vector<uint8_t>;

bytestring concat(const bytestring& a, const bytestring& b)
{
    bytestring result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

bytestring slice(const bytestring& values, size_t offset, size_t size)
{
    bytestring result;
    result.reserve(size);
    result.insert(result.end(), values.data() + offset, values.data() + offset + size);
    return result;
}

std::vector<string> split(string s, string delim)
{
    std::vector<string> result;
    size_t start = 0;
    size_t end = s.find(delim);
    while (end != string::npos)
    {
        result.push_back(s.substr(start, end - start));
        start = end + delim.length();
        end = s.find(delim, start);
    }
    result.push_back(s.substr(start, end));
    return result;
}

class Bech32
{
    static uint32_t polymod(const bytestring& values);
    static bool verifyChecksum(const bytestring& values);
public:
    static bytestring decode(const string& str);
};

uint32_t Bech32::polymod(const bytestring& values)
{
    uint32_t result = 1;
    for (size_t i = 0; i < values.size(); i++)
    {
        const uint8_t b = result >> 25;

        result = ((result & 0x1ffffff) << 5) ^ values[i];

        if (b & 0x01) result ^= 0x3b6a57b2;
        if (b & 0x02) result ^= 0x26508e6d;
        if (b & 0x04) result ^= 0x1ea119fa;
        if (b & 0x08) result ^= 0x3d4233dd;
        if (b & 0x10) result ^= 0x2a1462b3;
    }
    return result;
}

bool Bech32::verifyChecksum(const bytestring& values)
{
    const uint32_t checksum = polymod(concat({0},values));
    return checksum == 0x3fffffff;
}

bytestring Bech32::decode(const string& str) {
    // 32 indicates invalid
    const uint8_t table[128] = {
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
        15, 32, 10, 17, 21, 20, 26, 30,  7,  5, 32, 32, 32, 32, 32, 32,
        32, 29, 32, 24, 13, 25,  9,  8, 23, 32, 18, 22, 31, 27, 19, 32,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, 32, 32, 32, 32, 32,
        32, 29, 32, 24, 13, 25,  9,  8, 23, 32, 18, 22, 31, 27, 19, 32,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, 32, 32, 32, 32, 32
    };

    // convert bech32 characters to 5 bit values (stored in 8 bits)
    bytestring result(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        uint8_t c = str[i];
        int8_t rev = c < 128 ? table[c] : 32;
        if (rev == 32) {
            return bytestring();
        }
        result[i] = rev;
    }

    if (!verifyChecksum(result)) {
        return bytestring();
    }

    // convert from 5 to 8 bit, reusing the same vector

    const size_t len = result.size() - 6; // last 6 values used for checksum
    size_t j = 0;
    uint32_t acc = 0;
    uint32_t bits = 0;

    for (size_t i = 0; i < len; ++i) {
        const uint8_t value = result[i];
        acc = (acc<<5) | value;
        bits += 5;
        if (bits & 8) {
            bits &= 7;
            result[j++] = (acc >> bits) & 0xff;
        }
    }
    result.resize(j);
    result.shrink_to_fit();

    return result;
}

class CBOR
{
    static size_t decodeByteStringLength(const bytestring& values, size_t offset, size_t n);
public:
    static bytestring decodeByteString(const bytestring& values);
};

size_t CBOR::decodeByteStringLength(const bytestring& values, size_t offset, size_t n)
{
    size_t result = 0;
    while (n--)
    {
        result <<= 8;
        result |= values[offset++];
    }
    return result;
}

bytestring CBOR::decodeByteString(const bytestring& values) {
    const uint8_t header = values[0];
    if (header >= 0x40 && header < 0x58) {
        const size_t dataLength = header - 0x40;
        return slice(values, 1, dataLength);
    }
    if (header == 0x58) {
        const size_t dataLength = decodeByteStringLength(values, 1, 1);
        return slice(values, 2, dataLength);
    }
    if (header == 0x59) {
        const size_t dataLength = decodeByteStringLength(values, 1, 2);
        return slice(values, 3, dataLength);
    }
    if (header == 0x5a) {
        const size_t dataLength = decodeByteStringLength(values, 1, 4);
        return slice(values, 5, dataLength);
    }
    if (header == 0x5b) {
        const size_t dataLength = decodeByteStringLength(values, 1, 8);
        return slice(values, 5, dataLength);
    }
    // this wasn't a cbor byte string
    return bytestring();
}

class Base64
{
public:
    static string encode(const bytestring& values);
};

string Base64::encode(const bytestring& values)
{
    const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t* src = values.data();
    const size_t len = values.size();
    const size_t resultLen = len == 0 ? 0 : (len + 2) / 3 * 4;

    string result;
    result.reserve(resultLen);

    size_t i = 0;
    size_t j;

    while (i + 3 <= len) {
        j = src[i] >> 2;
        result.push_back(table[j]);
        j = (src[i++] & 0x03) << 4;
        j |= src[i] >> 4;
        result.push_back(table[j]);
        j = (src[i++] & 0x0f) << 2;
        j |= src[i] >> 6;
        result.push_back(table[j]);
        j = src[i++] & 0x3f;
        result.push_back(table[j]);
    }

    if ( i != len ) {
        j = src[i] >> 2;
        result.push_back(table[j]);
        j = (src[i++] & 0x03) << 4;
        if (i == len) {
            result.push_back(table[j]);
            result.push_back( '=');
        } else {
            j |= src[i] >> 4;
            result.push_back(table[j]);
            j = (src[i] & 0x0f) << 2;
            result.push_back(table[j]);
        }
        result.push_back( '=');
    }
    assert(result.length() == resultLen);
    return result;
}

struct Sequence
{
    size_t index;
    size_t total;

    Sequence(const string& s)
    {
        const size_t pos = s.find("OF");
        if (pos == 0 || pos == string::npos || pos == s.length() - 2)
        {
		index = 0;
		total = 0;
	}
	else
	{
            // note: the sequence index in the string is 1-based, we use 0 based
            index = std::stoi(s.substr(0,pos)) - 1;
            total = std::stoi(s.substr(pos+2));
        }
    }

    bool valid() const
    {
        return total != 0 && index < total;
    }
};

bool URBytesDecoder::Segments::complete() const
{
    std::vector<string>::const_iterator it;
    for (it = values.begin(); it != values.end(); ++it)
    {
        if (it->empty())
        {
            return false;
        }
    }
    return true;
}

string URBytesDecoder::Segments::combine() const
{
    string result;
    std::vector<string>::const_iterator it;
    for (it = values.begin(); it != values.end(); ++it)
    {
        result += *it;
    }
    return result;
}

void URBytesDecoder::Segments::add(size_t index, size_t total, const string& encodedDigest, const string& segment)
{
    if (encodedDigest != this->encodedDigest)
    {
        values.clear();
        this->encodedDigest = encodedDigest;
    }
    values.resize(total);
    values[index] = segment;
}

string URBytesDecoder::parse(string message)
{
    const string header("UR:BYTES/");

    if (message.compare(0,header.size(),header) != 0)
    {
        // not for us
        return string();
    }

    const std::vector<string> v = split(message,"/");

    if (v.size() == 2)
    {
        const string& encodedPayload = v[1];
        const bytestring payloadCBOR = Bech32::decode(encodedPayload);
        return finalize(payloadCBOR);
    }
    if (v.size() == 3)
    {
        const string& encodedDigest = v[1];
        const string& encodedPayload = v[2];
        const bytestring payloadCBOR = Bech32::decode(encodedPayload);
        return finalize(encodedDigest, payloadCBOR);
    }
    if (v.size() == 4)
    {
        const string& sequenceString = v[1];
        const string& encodedDigest = v[2];
        const string& segment = v[3];
        const Sequence seq(sequenceString);
        if (seq.valid())
        {
            segments.add(seq.index, seq.total, encodedDigest, segment);
            if (segments.complete())
            {
                const string encodedPayload = segments.combine();
                const bytestring payloadCBOR = Bech32::decode(encodedPayload);
                return finalize(encodedDigest, payloadCBOR);
            }
        }
    }
    return string();
}

string URBytesDecoder::finalize(const bytestring& payloadCBOR)
{
    return Base64::encode(CBOR::decodeByteString(payloadCBOR));
}

string URBytesDecoder::finalize(const string& encodedDigest, const bytestring& payloadCBOR)
{
    std::array<uint8_t,32> digest;
    const bytestring tmp = Bech32::decode(encodedDigest);
    if (tmp.size() != 32)
    {
        return string();
    }
    std::copy(tmp.begin(), tmp.end(), digest.begin());

    std::array<uint8_t,32> check;
    sha256_easy_hash(payloadCBOR.data(), payloadCBOR.size(), check.data());

    if (check != digest)
    {
        return string();
    }

    return finalize(payloadCBOR);
}

// C-wrapper

struct urbytesdecoder_s
{
    URBytesDecoder* impl;
};

urbytesdecoder_t* urbytesdecoder_create()
{
    urbytesdecoder_t* instance = (urbytesdecoder_t*)malloc(sizeof(urbytesdecoder_s));
    instance->impl = new URBytesDecoder;
    return instance;
}

void urbytesdecoder_destroy(urbytesdecoder_t* instance)
{
    delete instance->impl;
    free(instance);
}

char* urbytesdecoder_parse(urbytesdecoder_t* instance, const char* str, size_t n)
{
    string payloadBase64 = instance->impl->parse(string(str,n));
    if (payloadBase64.empty()) return 0;
    char* copy = (char*)malloc(payloadBase64.size()+1);
    std::memcpy(copy, payloadBase64.data(), payloadBase64.size() + 1);
    return copy;
}
