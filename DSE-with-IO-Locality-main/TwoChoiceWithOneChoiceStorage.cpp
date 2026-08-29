#include "TwoChoiceWithOneChoiceStorage.h"
#include<string.h>

TwoChoiceWithOneChoiceStorage::TwoChoiceWithOneChoiceStorage(bool inMemory, long dataIndex, string fileAddressPrefix, bool profile) {
    this->inMemoryStorage = inMemory;
    this->fileAddressPrefix = fileAddressPrefix;
    this->dataIndex = dataIndex;
    this->profile = profile;
    memset(nullKey.data(), 0, AES_KEY_SIZE);

    for (long i = 0; i < dataIndex; i++) {
        long curNumberOfBins = i > 3 ? ((long) ceil((float) pow(2, i) / ((log2(log2(pow(2, i))))*(log2(log2(log2(pow(2, i)))))*(log2(log2(log2(pow(2, i)))))))) : 1;
        curNumberOfBins = pow(2, (long) ceil(log2(curNumberOfBins)));
        long curSizeOfEachBin = i > 3 ? SPACE_OVERHEAD * (log2(log2(pow(2, i))))*(log2(log2(log2(pow(2, i)))))*(log2(log2(log2(pow(2, i))))) : SPACE_OVERHEAD * pow(2, i);
//        cout << "level:" << i << " number of bins:" << curNumberOfBins << " size of bins:" << curSizeOfEachBin << endl;
        numberOfBins.push_back(curNumberOfBins);
        sizeOfEachBin.push_back(curSizeOfEachBin);
        //printf("TwoChoiceWithOneChoiceStorage Level:%d number of Bins:%d size of bin:%d\n", i, curNumberOfBins, curSizeOfEachBin);
    }
//    cout << endl;
}

bool TwoChoiceWithOneChoiceStorage::isInCache(long index, long pos) {
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
FILE* TwoChoiceWithOneChoiceStorage::getHandle(long index) {
    if ((long) handles.size() <= index) {
        handles.resize(index + 1, nullptr);
    }
    if (handles[index] == nullptr) {
        handles[index] = fopen(filenames[index].c_str(), "rb+");
    }
    return handles[index];
}

void TwoChoiceWithOneChoiceStorage::closeActiveHandle(long index) {
    if (index >= 0 && (long) handles.size() > index && handles[index] != nullptr) {
        fflush(handles[index]);
        fclose(handles[index]);
        handles[index] = nullptr;
    }
}

bool TwoChoiceWithOneChoiceStorage::setup(bool overwrite) {
    for (long i = 0; i < dataIndex; i++) {
        string filename = fileAddressPrefix + "MAP-" + to_string(i) + ".dat";
        filenames.push_back(filename);
        Utilities::ensureFileExists(filename, overwrite);
        data.push_back(vector< vector<prf_type> >());
    }
    return true;
}

void TwoChoiceWithOneChoiceStorage::insertStash(long index, vector<prf_type> ciphers) {
    string st = fileAddressPrefix + "STASH-" + to_string(index) + ".dat";
    //fstream file(st, ios::binary | ios::out);
    FILE* file = fopen(st.c_str(), "wb");
    if (file == NULL) {
        cout << "StashXX:" << index << endl;
        cerr << "(Error in Stash insert: " << strerror(errno) << ")" << endl;
    }
    for (auto item : ciphers) {
        unsigned char newRecord[AES_KEY_SIZE];
        memset(newRecord, 0, AES_KEY_SIZE);
        std::copy(item.begin(), item.end(), newRecord);
        //        file.write((char*) newRecord, AES_KEY_SIZE);
        fwrite((char*) newRecord, AES_KEY_SIZE, 1, file);
    }
    //    file.close();
    fclose(file);
}

void TwoChoiceWithOneChoiceStorage::insertAll(long index, vector<vector< prf_type > > ciphers, bool append, bool firstRun, bool setupMode) {
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
                    //                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                    memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) pair.data(), AES_KEY_SIZE);
                    tmpcnt++;
                }
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            setupHeadPos += totalSize;
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
                    //                    fwrite((char*) pair.data(), AES_KEY_SIZE, 1, file);
                    memcpy(&tmpData[tmpcnt * AES_KEY_SIZE], (char*) pair.data(), AES_KEY_SIZE);
                    tmpcnt++;
                }
            }

            fwrite((char*) tmpData, totalSize, 1, file);
            setupHeadPos = totalSize;
            fflush(file);
            delete[] tmpData;
        }
    } else {
        if (append && !firstRun) {
            fstream file(filenames[index].c_str(), ios::binary | std::ios::app);
            if (file.fail()) {
                cerr << "Error in insert: " << strerror(errno);
            }
            for (auto item : ciphers) {
                for (auto pair : item) {
                    file.write((char*) pair.data(), AES_KEY_SIZE);
                }
            }
            file.close();
        } else {
            fstream file(filenames[index].c_str(), ios::binary | ios::out);
            if (file.fail()) {
                cerr << "Error in insert: " << strerror(errno);
            }
            for (auto item : ciphers) {
                for (auto pair : item) {
                    file.write((char*) pair.data(), AES_KEY_SIZE);
                }
            }
            file.close();
        }
    }
}

vector<prf_type> TwoChoiceWithOneChoiceStorage::getAllData(long index) {
    vector<prf_type> results;
    fstream file(filenames[index].c_str(), ios::binary | ios::in | ios::ate);
    if (file.fail()) {
        cerr << "Error in read: " << strerror(errno);
    }
    long size = file.tellg();
    //cout <<"getAll size:"<<size<<endl;
    if (Utilities::DROP_CACHE) {
        Utilities::startTimer(113);
        if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
        if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
        auto t = Utilities::stopTimer(113);
        //printf("drop cache time:%f\n", t);
        cacheTime += t;
    }
    file.seekg(0, ios::beg);
    char* keyValues = new char[size];
    file.read(keyValues, size);
    file.close();

    for (long i = 0; i < size / AES_KEY_SIZE; i++) {
        //cout <<"i is:"<<i<<endl;
        prf_type tmp;
        std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
        results.push_back(tmp);
    }
    delete[] keyValues;
    return results;
}

void TwoChoiceWithOneChoiceStorage::clear(long index) {
    fstream file(filenames[index].c_str(), std::ios::binary | std::ofstream::out);
    if (file.fail())
        cerr << "Error: " << strerror(errno);
    long maxSize = numberOfBins[index] * sizeOfEachBin[index];
    for (long j = 0; j < maxSize; j++) {
        file.write((char*) nullKey.data(), AES_KEY_SIZE);
    }
    file.close();
}

TwoChoiceWithOneChoiceStorage::~TwoChoiceWithOneChoiceStorage() {
    for (long i = 0; i < (long) handles.size(); i++) {
        closeActiveHandle(i);
    }
}

vector<prf_type> TwoChoiceWithOneChoiceStorage::find(long index, prf_type mapKey, long cnt) {
    Utilities::startTimer(69);
    //searchTime = 0;
    auto previousCacheTime = cacheTime;
    vector<prf_type> results;
    //std::fstream file(filenames[index].c_str(), ios::binary | ios::in);

    //    if (file.fail()) {
    //FILE* file = fopen(filenames[index].c_str(),"rb");
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
    if (cnt >= numberOfBins[index]) {
        long fileLength = numberOfBins[index] * sizeOfEachBin[index] * AES_KEY_SIZE - floor(numberOfBins[index] * Utilities::CACHE_PERCENTAGE) * sizeOfEachBin[index] * AES_KEY_SIZE;
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        //        file.seekg(0, ios::beg);
        fseek(file, floor(numberOfBins[index] * Utilities::CACHE_PERCENTAGE) * sizeOfEachBin[index] * AES_KEY_SIZE, SEEK_SET);

        char* keyValues = new char[fileLength];
        memset(keyValues, 0, fileLength); // unwritten tail (level not fully grown yet) reads back as empty slots
        fread(keyValues, fileLength, 1, file);
        SeekG++;
        int cacheRead = 0;
        for (long i = 0; i < data[index].size(); i++) {
            for (long j = 0; j < data[index][i].size(); j++) {
                results.push_back(data[index][i][j]);
                cacheRead++;
            }
        }
        readBytes += fileLength;
        for (long i = 0; i < numberOfBins[index] * sizeOfEachBin[index] - cacheRead; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        delete[] keyValues;
    } else {
        long superBins = ceil((float) numberOfBins[index] / cnt);
        long pos = (unsigned long) (*((long*) hash)) % superBins; //numberOfBins[index];
        int cacheRead = 0;
        if (isInCache(index, pos * cnt)) {
            long newCnt = cnt;
            for (long j = pos * cnt; j < min(pos * cnt + cnt, (long) data[index].size()); j++) {
                for (long i = 0; i < data[index][j].size(); i++) {
                    results.push_back(data[index][j][i]);
                    cacheRead++;
                }
                newCnt--;
            }
            pos = min(pos * cnt + cnt, (long) data[index].size());
            cnt = newCnt;
        } else {
            pos = pos*cnt;
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
        if (Utilities::DROP_CACHE) {
            Utilities::startTimer(113);
            if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
            if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
            auto t = Utilities::stopTimer(113);
            cacheTime += t;
        }
        //        file.seekg(readPos, ios::beg);
        fseek(file, readPos, SEEK_SET);
        SeekG++;
        char* keyValues = new char[readLength];
        memset(keyValues, 0, readLength); // unwritten tail (level not fully grown yet) reads back as empty slots
        fread(keyValues, readLength, 1, file);
        readBytes += readLength;
        for (long i = 0; i < readLength / AES_KEY_SIZE; i++) {
            prf_type tmp;
            std::copy(keyValues + i*AES_KEY_SIZE, keyValues + i * AES_KEY_SIZE + AES_KEY_SIZE, tmp.begin());
            results.push_back(tmp);
        }
        delete[] keyValues;
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

            if (Utilities::DROP_CACHE) {
                Utilities::startTimer(113);
                if (Utilities::HDD_CACHE)system(Utilities::HDD_DROP_CACHE_COMMAND.c_str()); if (Utilities::SSD_CACHE)system(Utilities::SSD_DROP_CACHE_COMMAND.c_str());
                if (Utilities::KERNEL_CACHE)system(Utilities::KERNEL_DROP_CACHE_COMMAND.c_str());
                auto t = Utilities::stopTimer(113);
                cacheTime += t;
            }
            //file.seekg(0, ios::beg);
            fseek(file, readPos, SEEK_SET);
            readLength = cnt * AES_KEY_SIZE * sizeOfEachBin[index];
            char* keyValues = new char[readLength];
            memset(keyValues, 0, readLength); // unwritten tail (level not fully grown yet) reads back as empty slots
            fread(keyValues, readLength, 1, file);
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
    //    file.close();
    //fclose(file);
    auto t = Utilities::stopTimer(69);
    searchTime = t - (cacheTime - previousCacheTime);
    if (ownsHandle) {
        fclose(file);
    }
    return results;
}

void TwoChoiceWithOneChoiceStorage::loadCache() {
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