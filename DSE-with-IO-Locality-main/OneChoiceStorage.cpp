#include "OneChoiceStorage.h"
#include "OneChoiceSDdGeneralServer.h"
#include <math.h>

OneChoiceStorage::OneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);
    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 1 ? (long) ceil((float) pow(2, i) / (float) (log2(pow(2, i)) * log2(log2(pow(2, i))))) : 1;
        long curSizeOfEachBin = i > 1 ? 3 * (log2(pow(2, i)) * log2(log2(pow(2, i)))) : pow(2, i);
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
    }

}

bool OneChoiceStorage::isInCache(long index, long pos) {
    long levelSize = numberOfBins[index];
    long threshold = floor(levelSize * Utilities::CACHE_PERCENTAGE);
    if (pos < threshold) {
        return true;
    } else {
        return false;
    }
}

// Returns the handle for filenames[index], opening it on first access and caching
// it (one handle per level) until closeActiveHandle(index) is called explicitly.
FILE* OneChoiceStorage::getHandle(long index) {
    if ((long) handles.size() <= index) {
        handles.resize(index + 1, nullptr);
    }
    if (handles[index] == nullptr) {
        handles[index] = fopen(filenames[index].c_str(), "rb+");
    }
    return handles[index];
}

void OneChoiceStorage::closeActiveHandle(long index) {
    if (index >= 0 && (long) handles.size() > index && handles[index] != nullptr) {
        fflush(handles[index]);
        fclose(handles[index]);
        handles[index] = nullptr;
    }
}

OneChoiceStorage::~OneChoiceStorage() {
    for (long i = 0; i < (long) handles.size(); i++) {
        closeActiveHandle(i);
    }
}

bool OneChoiceStorage::setup(bool overwrite) {

    for (long i = 0; i < dataIndex; i++) {
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        Utilities::ensureFileExists(filename, overwrite);
        data.push_back(vector< vector<prf_type> >());
    }
    return true;
}

void OneChoiceStorage::insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun, bool setupMode) {
    if (setupMode) {
        if (append && !firstRun) {
            FILE* file = getHandle(index);

            fseek(file, setupHeadPos, SEEK_SET);
            long totalSize = 0;
            for (auto item : ciphers) {
                totalSize += AES_KEY_SIZE * item.size();
            }

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                for (auto pair : item) {
                    memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) pair.data(), AES_KEY_SIZE);
                    tmpcnt++;
                }
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            setupHeadPos += totalSize;
            fflush(file);
            delete[] tmpData;
        } else {
            setupHeadPos = 0;
            FILE* file = getHandle(index);
            fseek(file, 0L, SEEK_SET);

            long totalSize = 0;
            for (auto item : ciphers) {
                totalSize += AES_KEY_SIZE * item.size();
            }

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                for (auto pair : item) {
                    memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) pair.data(), AES_KEY_SIZE);
                    tmpcnt++;
                }
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            fflush(file);
            setupHeadPos = totalSize;
            delete[] tmpData;
        }
    } else {
        if (append && !firstRun) {
            FILE* file = getHandle(index);

            fseek(file, 0, SEEK_END);
            for (auto item : ciphers) {
                for (auto pair : item) {
                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                }
            }
        } else {
            FILE* file = getHandle(index);
            fseek(file, 0L, SEEK_SET);
            for (auto item : ciphers) {
                for (auto pair : item) {
                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                }
            }
            fflush(file);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
        }
    }
}

void OneChoiceStorage::insertAll(long index, vector< prf_type > ciphers, bool append, bool firstRun, bool setupMode) {
    if (setupMode) {
        if (append && !firstRun) {
            FILE* file = getHandle(index);

            fseek(file, 0, SEEK_END);
            long totalSize = AES_KEY_SIZE * ciphers.size();

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) item.data(), AES_KEY_SIZE);
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            delete[] tmpData;

        } else {
            FILE* file = getHandle(index);
            fseek(file, 0L, SEEK_SET);

            long totalSize = AES_KEY_SIZE * ciphers.size();

            char* tmpData = new char[totalSize];

            long tmpcnt = 0;
            for (auto item : ciphers) {
                memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) item.data(), AES_KEY_SIZE);
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            fflush(file);
            delete[] tmpData;
        }
    } else {
        if (append && !firstRun) {
            FILE* file = getHandle(index);
            fseek(file, 0, SEEK_END);
            for (auto item : ciphers) {
                fwrite((char*) item.data(), AES_KEY_SIZE, 1, file);
            }
        } else {
            FILE* file = getHandle(index);
            fseek(file, 0L, SEEK_SET);
            for (auto item : ciphers) {
                fwrite((char*) item.data(), AES_KEY_SIZE, 1, file);
            }
            fflush(file);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
        }
    }
}

vector<prf_type> OneChoiceStorage::getAllDataFlat(long index) {

    vector<prf_type > results;
    FILE* file = getHandle(index);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    fseek(file, 0L, SEEK_SET);
    char* keyValues = new char[size];
    fread(keyValues, size, 1, file);
    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }

    delete[] keyValues;

    return results;
}

vector<vector<prf_type> >* OneChoiceStorage::getAllData(long index) {

    vector<vector<prf_type> >* results = new vector<vector<prf_type> >();
    FILE* file = getHandle(index);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    fseek(file, 0L, SEEK_END);
    long size = ftell(file);
    fseek(file, 0L, SEEK_SET);
    char* keyValues = new char[size];
    fread(keyValues, size, 1, file);
    int counter = 0;
    vector<prf_type> tmpRes;
    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        tmpRes.push_back(tmp);
        counter++;
        if (counter == sizeOfEachBin[index]) {
            results->push_back(tmpRes);
            tmpRes.clear();
            counter = 0;
        }
    }

    delete[] keyValues;

    return results;
}

void OneChoiceStorage::clear(long index) {
    FILE* file = getHandle(index);
    fseek(file, 0L, SEEK_SET);
    long maxSize = numberOfBins[index] * sizeOfEachBin[index];
    for (long j = 0; j < maxSize; j++) {
        fwrite((char*) nullKey.data(), AES_KEY_SIZE, 1, file);
    }
    fflush(file);
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
}

vector<prf_type> OneChoiceStorage::find(long index, prf_type mapKey, long cnt) {
    Utilities::startTimer(104);
    Utilities::startTimer(610);
    auto previousCacheTime = cacheTime;
    vector<prf_type> results;
    FILE* file;
    bool ownsHandle = Utilities::useRandomFolder;
    if (Utilities::useRandomFolder) {
        file = fopen(filenames[index].c_str(), "rb+");
    } else {
        file = getHandle(index);
    }
    if (file == NULL) {
        cerr << "Error in read: " << strerror(errno);
    }

    unsigned char* hash = Utilities::sha256((char*) mapKey.data(), AES_KEY_SIZE);
    auto hh = Utilities::stopTimer(610);
    if (cnt >= numberOfBins[index]) {
        int cacheRead = 0;
        for (long i = 0; i < data[index].size(); i++) {
            for (long j = 0; j < data[index][i].size(); j++) {
                results.push_back(data[index][i][j]);
                cacheRead++;
            }
        }
        if (numberOfBins[index] * sizeOfEachBin[index] - cacheRead > 0) {
            //read everything
            long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE - floor(numberOfBins[index] * Utilities::CACHE_PERCENTAGE) * sizeOfEachBin[index] * AES_KEY_SIZE;
            fseek(file, floor(numberOfBins[index] * Utilities::CACHE_PERCENTAGE) * sizeOfEachBin[index] * AES_KEY_SIZE, SEEK_SET);
            char* keyValues = new char[fileLength];
            // Levels are no longer zero-preallocated to full capacity up front, so a
            // level that hasn't been fully written yet may be shorter than fileLength;
            // zero the buffer first so the unwritten tail reads back as empty slots.
            memset(keyValues, 0, fileLength);
            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
            Utilities::startTimer(610);
            fread(keyValues, fileLength, 1, file);
            auto ss = Utilities::stopTimer(610);
            SeekG++;
            readBytes += fileLength;

            for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index] - cacheRead; i++) {
                prf_type tmp;
                std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }
            delete[] keyValues;
        }
    } else {
        Utilities::startTimer(610);
        long pos = (unsigned long) (*((long*) hash)) % numberOfBins[index];
        int cacheRead = 0;
        if (isInCache(index, pos)) {
            long newCnt = cnt;
            for (long j = pos; j < min(pos + cnt, (long) data[index].size()); j++) {
                for (long i = 0; i < data[index][j].size(); i++) {
                    results.push_back(data[index][j][i]);
                    cacheRead++;
                }
                newCnt--;
            }
            pos = min(pos + cnt, (long) data[index].size());
            cnt = newCnt;
        }
        if (cnt == 0) {
            auto t = Utilities::stopTimer(104);
            searchTime = t - (cacheTime - previousCacheTime);
            if (ownsHandle) {
                fclose(file);
            }
            return results;
        }

        long readPos = pos * AES_KEY_SIZE * sizeOfEachBin[index];
        long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE;
        long remainder = fileLength - readPos;
        long totalReadLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
        long readLength = 0;
        if (totalReadLength > remainder) {
            readLength = remainder;
            totalReadLength -= remainder;
        } else {
            readLength = totalReadLength;
            totalReadLength = 0;
        }
        hh = Utilities::stopTimer(610);
        if (Utilities::DROP_CACHE && !setupMode) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        Utilities::startTimer(610);
        fseek(file, readPos, SEEK_SET);
        auto zz = Utilities::stopTimer(610);
        SeekG++;
        char* keyValues = new char[readLength];
        memset(keyValues, 0, readLength); // unwritten tail (level not fully grown yet) reads back as empty slots
        Utilities::startTimer(610);
        fread(keyValues, readLength, 1, file);
        auto ss = Utilities::stopTimer(610);
        Utilities::startTimer(610);
        readBytes += readLength;
        for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        delete[] keyValues;
        ss = Utilities::stopTimer(610);
        if (totalReadLength > 0) {
            readLength = totalReadLength;
            cnt = readLength / (AES_KEY_SIZE * sizeOfEachBin[index]);
            pos = 0;

            cacheRead = 0;
            if (isInCache(index, pos)) {
                long newCnt = cnt;
                for (long j = pos; j < min(pos + cnt, (long) data[index].size()); j++) {
                    for (long i = 0; i < data[index][j].size(); i++) {
                        results.push_back(data[index][j][i]);
                        cacheRead++;
                    }
                    newCnt--;
                }
                pos = min(pos + cnt, (long) data[index].size());
                cnt = newCnt;

            }
            readPos = pos * AES_KEY_SIZE * sizeOfEachBin[index];


            if (Utilities::DROP_CACHE && !setupMode) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
            fseek(file, readPos, SEEK_SET);
            readLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
            char* keyValues = new char[readLength];
            memset(keyValues, 0, readLength); // unwritten tail (level not fully grown yet) reads back as empty slots
            Utilities::startTimer(610);
            fread(keyValues, readLength, 1, file);
            ss = Utilities::stopTimer(610);
            readBytes += readLength;
            SeekG++;
            for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
                prf_type tmp;
                std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                results.push_back(tmp);
            }

            delete[] keyValues;
        }
    }
    Utilities::startTimer(610);
    hh = Utilities::stopTimer(610);
    auto t = Utilities::stopTimer(104);
    searchTime = t - (cacheTime - previousCacheTime);
    if (ownsHandle) {
        fclose(file);
    }
    return results;
}

string OneChoiceStorage::getName(long dataIndex) {
    return filenames[dataIndex];
}

void OneChoiceStorage::closeHandle(long index) {
    closeActiveHandle(index);
}

void OneChoiceStorage::rename(long toIndex, string inputFileName) {
    closeActiveHandle(toIndex);
    std::remove(filenames[toIndex].c_str()); // POSIX rename() replaces an existing destination; Windows' does not
    if (std::rename(inputFileName.c_str(), filenames[toIndex].c_str()) != 0) {
        perror("Error renaming file");
    }
}

void OneChoiceStorage::resetup(long index) {
    closeActiveHandle(index);
    string filename = filenames[index];
    fstream file(filename.c_str(), std::ofstream::out);
    if (file.fail()) {
        cerr << "Error: " << strerror(errno);
    }
    long maxSize = numberOfBins[index] * sizeOfEachBin[index];
    if (Utilities::DROP_CACHE && !setupMode) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        cacheTime += t;
    }
    file.seekp(maxSize * AES_KEY_SIZE - AES_KEY_SIZE);
    file.write((char*) nullKey.data(), AES_KEY_SIZE);
    file.close();
}

void OneChoiceStorage::loadCache() {
    if (Utilities::CACHE_PERCENTAGE == 0) {
        return;
    }
    for (long index = 0; index < dataIndex; index++) {
        long levelSize = numberOfBins[index];
        long size = floor(levelSize * Utilities::CACHE_PERCENTAGE);
        FILE* file = getHandle(index);
        if (file == NULL) {
            cerr << "Error in read: " << strerror(errno);
        }
        fseek(file, 0L, SEEK_SET);

        char* keyValue = new char[size * sizeOfEachBin[index] * AES_KEY_SIZE];
        memset(keyValue, 0, size * sizeOfEachBin[index] * AES_KEY_SIZE); // unwritten tail reads back as empty slots
        fread(keyValue, size * sizeOfEachBin[index] * AES_KEY_SIZE, 1, file);

        for (long i = 0; i < size; i++) {
            vector<prf_type> col;
            for (int j = 0; j < sizeOfEachBin[index]; j++) {
                prf_type tmp;
                std::copy(keyValue + i * (sizeOfEachBin[index] * AES_KEY_SIZE) + j * AES_KEY_SIZE, keyValue + i * (sizeOfEachBin[index] * AES_KEY_SIZE) + j * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
                col.push_back(tmp);
            }
            data[index].push_back(col);
        }

        delete[] keyValue;
    }
}
