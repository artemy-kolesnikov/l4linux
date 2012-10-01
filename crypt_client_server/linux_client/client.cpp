/**
 * client.cpp: Linux client code
 *
 * (c) 2012 Artemy Kolesnikov <artemy.kolesnikov@gmail.com>
 */

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sstream>

#define IOCTL_MAGIC '^'
#define IOCTL_ENCRYPT _IO(IOCTL_MAGIC, 1)
#define IOCTL_DECRYPT _IO(IOCTL_MAGIC, 2)

namespace {

const char* ENCRYPT_CMD = "encrypt";
const char* DECRYPT_CMD = "decrypt";

enum CryptServerOperation {
    ENCRYPT_OP = IOCTL_ENCRYPT,
    DECRYPT_OP = IOCTL_DECRYPT
};

const char* CRYPT_DEVICE_FILE = "/dev/crypt";

class ErrorString {
public:
    operator std::string () const {
        return sstr.str();
    }

    ErrorString& operator << (const char* msg) {
        sstr << msg;
        return *this;
    }

    ErrorString& operator << (std::string msg) {
        sstr << msg;
        return *this;
    }

private:
    std::stringstream sstr;
};

class UnixFile {
public:
    UnixFile(const char* filePath, int flags) {
        fd = open(filePath, flags);
    }

    ~UnixFile() {
        close(fd);
    }

    bool isOpen() const {
        return fd != -1;
    }

    size_t read(char* buffer, size_t size) {
        int ret;
        while (size != 0 && (ret = ::read(fd, buffer, size)) != 0) {
            if (-1 == ret) {
                if (EINTR == errno) {
                    continue;
                }
                throw std::runtime_error(ErrorString() << "Cannot read data from file: " << strerror(errno));
            }

            size -= ret;
            buffer += ret;
        }

        return ret > 0 ? ret : 0;
    }

    size_t write(const char* buffer, size_t size) {
        int ret;
        while (size != 0 && (ret = ::write(fd, buffer, size)) != 0) {
            if (-1 == ret) {
                if (EINTR == errno) {
                    continue;
                }
                throw std::runtime_error(ErrorString() << "Cannot write data to file: " << strerror(errno));
            }

            size -= ret;
            buffer += ret;
        }

        return ret > 0 ? ret : 0;
    }

    int ioctl(unsigned int cmd, unsigned int arg) {
        return ::ioctl(fd, cmd, arg);
    }

private:
    int fd;
};

void invokeCryptSrverOp(const std::string& inputFilePath, const std::string& outputFilePath, CryptServerOperation op) {
    std::ifstream in(inputFilePath.c_str());
    if (!in.is_open()) {
        throw std::runtime_error(ErrorString() << "Cannot open " << inputFilePath << " file");
    }

    in.seekg(0, std::ios::end);
    size_t inputFileSize = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<char> buf(inputFileSize);
    in.read(&buf.front(), buf.size());

    UnixFile cryptDeviceFile(CRYPT_DEVICE_FILE, O_RDWR);
    if (!cryptDeviceFile.isOpen()) {
        throw std::runtime_error(ErrorString() << "Cannot open " << CRYPT_DEVICE_FILE << " file");
    }

    std::vector<char> resultBuf(buf.size());

    cryptDeviceFile.write(&buf.front(), buf.size());
    cryptDeviceFile.ioctl(op, 0);
    cryptDeviceFile.read(&resultBuf.front(), resultBuf.size());

    std::ofstream out(outputFilePath.c_str());
    if (!out.is_open())  {
        throw std::runtime_error(ErrorString() << "Cannot open " << outputFilePath << " file");
    }

    out.write(&resultBuf.front(), resultBuf.size());
}

void encrypt(const std::string& inputFilePath, const std::string& outputFilePath) {
    invokeCryptSrverOp(inputFilePath, outputFilePath, ENCRYPT_OP);
}

void decrypt(const std::string& inputFilePath, const std::string& outputFilePath) {
    invokeCryptSrverOp(inputFilePath, outputFilePath, DECRYPT_OP);
}

}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: crypt_client input_file output_file command\n";
        return 1;
    }

    std::string inputFile(argv[1]);
    std::string outputFile(argv[2]);
    std::string operation(argv[3]);

    try {
        if (ENCRYPT_CMD == operation) {
            encrypt(inputFile, outputFile);
        } else if (DECRYPT_CMD == operation) {
            decrypt(inputFile, outputFile);
        } else {
            throw std::runtime_error(ErrorString() << "Invalid operation " << operation);
        }
    } catch (const std::runtime_error& ex) {
        std::cerr << ex.what() << "\n";
        return -1;
    }

    return 0;
}
