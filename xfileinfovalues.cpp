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
#include "xfileinfovalues.h"

#include <QFileInfo>

XBinary::XIDSTRING _TABLE_XFIV[] = {
    {XFileInfoValues::XFIV_FILE_UNKNNOWN, QObject::tr("Unknown")},
    {XFileInfoValues::XFIV_FILE_SIZE, QObject::tr("Size")},
    {XFileInfoValues::XFIV_FILE_EXTENSION, QObject::tr("Extension")},
    {XFileInfoValues::XFIV_FILE_ENTROPY, QObject::tr("Entropy")},
};

bool XFileInfoValues_Sort::operator()(const XFileInfoValues::RecordInfo &recordInfo1, const XFileInfoValues::RecordInfo &recordInfo2) const
{
    if (recordInfo1.bIsDir != recordInfo2.bIsDir) {
        return recordInfo1.bIsDir;
    }

    if (xFIV == XFileInfoValues::XFIV_FILE_SIZE) {
        qint64 nSize1 = recordInfo1.mapValues.value(XFileInfoValues::XFIV_FILE_SIZE).toLongLong();
        qint64 nSize2 = recordInfo2.mapValues.value(XFileInfoValues::XFIV_FILE_SIZE).toLongLong();

        if (nSize1 != nSize2) {
            return (sortOrder == Qt::DescendingOrder) ? (nSize2 < nSize1) : (nSize1 < nSize2);
        }
    } else if (xFIV == XFileInfoValues::XFIV_FILE_EXTENSION) {
        QString sExtension1 = recordInfo1.mapValues.value(XFileInfoValues::XFIV_FILE_EXTENSION).toString().toCaseFolded();
        QString sExtension2 = recordInfo2.mapValues.value(XFileInfoValues::XFIV_FILE_EXTENSION).toString().toCaseFolded();

        if (sExtension1 != sExtension2) {
            return (sortOrder == Qt::DescendingOrder) ? (sExtension2 < sExtension1) : (sExtension1 < sExtension2);
        }
    } else if (xFIV == XFileInfoValues::XFIV_FILE_ENTROPY) {
        double dEntropy1 = recordInfo1.mapValues.value(XFileInfoValues::XFIV_FILE_ENTROPY).toDouble();
        double dEntropy2 = recordInfo2.mapValues.value(XFileInfoValues::XFIV_FILE_ENTROPY).toDouble();

        if (dEntropy1 != dEntropy2) {
            return (sortOrder == Qt::DescendingOrder) ? (dEntropy2 < dEntropy1) : (dEntropy1 < dEntropy2);
        }
    }

    QString sFileName1 = recordInfo1.sFileName.toCaseFolded();
    QString sFileName2 = recordInfo2.sFileName.toCaseFolded();

    if (sFileName1 == sFileName2) {
        return false;
    }

    return (sortOrder == Qt::DescendingOrder) ? (sFileName2 < sFileName1) : (sFileName1 < sFileName2);
}

XFileInfoValues::XFileInfoValues(QObject *pParent) : XThreadObject(pParent)
{
    m_pData = nullptr;
    m_pPdStruct = nullptr;
}

void XFileInfoValues::setData(XFIDATA *pData, XBinary::PDSTRUCT *pPdStruct)
{
    m_pData = pData;
    m_pPdStruct = pPdStruct;
}

void XFileInfoValues::process()
{
    if (!m_pData) {
        return;
    }

    qint32 nNumberOfFiles = m_pData->listRecords.count();
    qint32 nFreeIndex = XBinary::getFreeIndex(m_pPdStruct);
    XBinary::setPdStructInit(m_pPdStruct, nFreeIndex, nNumberOfFiles);

    for (qint32 i = 0; (i < nNumberOfFiles) && XBinary::isPdStructNotCanceled(m_pPdStruct); i++) {
        QString sFileName = m_pData->listRecords.at(i).sFilePath;

        XBinary::setPdStructStatus(m_pPdStruct, nFreeIndex, sFileName);
        m_pData->listRecords[i].mapValues = getValues(sFileName, &(m_pData->listFIV), m_pPdStruct);
        XBinary::setPdStructCurrent(m_pPdStruct, nFreeIndex, i + 1);
    }

    XBinary::setPdStructFinished(m_pPdStruct, nFreeIndex);
}

QString XFileInfoValues::getTitle()
{
    return tr("File info values");
}

QHash<XFileInfoValues::XFIV, QVariant> XFileInfoValues::getValues(const QString &sFileName, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct)
{
    QFile file(sFileName);

    QHash<XFileInfoValues::XFIV, QVariant> result;

    if (XBinary::isPdStructNotCanceled(pPdStruct) && file.open(QIODevice::ReadOnly)) {
        result = getValues(&file, pList, pPdStruct);
        file.close();
    } else {
        for (qint32 i = 0; i < pList->size(); i++) {
            result.insert(pList->at(i), QVariant());
        }
    }

    return result;
}

QHash<XFileInfoValues::XFIV, QVariant> XFileInfoValues::getValues(QIODevice *pDevice, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct)
{
    QHash<XFileInfoValues::XFIV, QVariant> result;

    for (qint32 i = 0; i < pList->size(); i++) {
        XFIV value = pList->at(i);

        if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
            result.insert(value, QVariant());
        } else if (value == XFIV_FILE_SIZE) {
            result.insert(value, XBinary::getSize(pDevice));
        } else if (value == XFIV_FILE_EXTENSION) {
            result.insert(value, XBinary::getDeviceFileSuffix(pDevice));
        } else if (value == XFIV_FILE_ENTROPY) {
            result.insert(value, XBinary::getEntropy(pDevice, pPdStruct));
        } else {
            result.insert(value, QVariant());
        }
    }

    return result;
}
