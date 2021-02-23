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

#ifdef __cplusplus

#include <vector>
#include <array>
#include <string>

class URBytesDecoder
{
    using string = std::string;
    using bytestring = std::vector<uint8_t>;

    class Segments
    {
        string encodedDigest;
        std::vector<string> values;
    public:
        bool complete() const;
        string combine() const;
        void add(size_t index, size_t total, const string& encodedDigest, const string& segment);
    };

    Segments segments;

    static string finalize(const bytestring& payloadCBOR);
    static string finalize(const string& encodedDigest, const bytestring& payloadCBOR);
public:
    string parse(string message);
};

extern "C"
{
#endif

#include <stddef.h>

struct urbytesdecoder_s;
typedef struct urbytesdecoder_s urbytesdecoder_t;

urbytesdecoder_t* urbytesdecoder_create();
void urbytesdecoder_destroy(urbytesdecoder_t* decoder);
char* urbytesdecoder_parse(urbytesdecoder_t* instance, const char* str, size_t n);

#ifdef __cplusplus
} // extern "C"
#endif
