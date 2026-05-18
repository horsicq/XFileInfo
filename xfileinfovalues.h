/* Copyright (c) 2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef XFILEINFOVALUES_H
#define XFILEINFOVALUES_H

#include "xformats.h"
#include "xthreadobject.h"

#include <QHash>
#include <QIcon>
#include <Qt>
#include <QVariant>

class XFileInfoValues : public XThreadObject {
    Q_OBJECT

public:
    enum XFIV  {
        XFIV_FILE_UNKNNOWN,
        XFIV_FILE_SIZE,
        XFIV_FILE_EXTENSION,
        XFIV_FILE_ENTROPY
    };

    struct RecordInfo {
        QString sFileName;
        QString sFilePath;
        QIcon icon;
        bool bIsDir;
        bool bEnabled;
        QHash<XFIV, QVariant> mapValues;
    };

    struct XFIDATA{
        QList<RecordInfo> listRecords;
        QList<XFIV> listFIV;
    };

    explicit XFileInfoValues(QObject *pParent = nullptr);

    void setData(XFIDATA *pData, XBinary::PDSTRUCT *pPdStruct = nullptr);

    void process() override;
    QString getTitle() override;

    static QHash<XFIV, QVariant> getValues(const QString &sFileName, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct);
    static QHash<XFIV, QVariant> getValues(QIODevice *pDevice, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct);

private:
    XFIDATA *m_pData;
    XBinary::PDSTRUCT *m_pPdStruct;
};

struct XFileInfoValues_Sort {
    Qt::SortOrder sortOrder = Qt::AscendingOrder;
    XFileInfoValues::XFIV xFIV = XFileInfoValues::XFIV_FILE_UNKNNOWN;

    bool operator()(const XFileInfoValues::RecordInfo &recordInfo1, const XFileInfoValues::RecordInfo &recordInfo2) const;
};

#endif  // XFILEINFOVALUES_H
