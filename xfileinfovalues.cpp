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
#include "xdisasmcore.h"

#include <QFileInfo>

namespace {
const qint64 N_XFIV_BYTES = 16;
const qint32 N_XFIV_SIGNATURECOUNT = 10;

bool isBinaryValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_HEADER_BYTES) || (value == XFileInfoValues::XFIV_ENTRYPOINT_BYTES) ||
           (value == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE) || (value == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE_RELATIVE) ||
           (value == XFileInfoValues::XFIV_OVERLAY_BYTES) || (value == XFileInfoValues::XFIV_OVERLAY_SIZE) ||
           (value == XFileInfoValues::XFIV_OVERLAY_ENTROPY);
}

QString readBytes(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    QString sResult;

    if ((nOffset >= 0) && (nSize > 0)) {
        QByteArray baData = XBinary::read_array_process(pDevice, nOffset, qMin(N_XFIV_BYTES, nSize), pPdStruct);
        sResult = QString::fromLatin1(baData.toHex().toUpper());
    }

    return sResult;
}
}  // namespace

XBinary::XIDSTRING _TABLE_XFIV[] = {
    {XFileInfoValues::XFIV_NAME, QObject::tr("Name")},
    {XFileInfoValues::XFIV_SIZE, QObject::tr("Size")},
    {XFileInfoValues::XFIV_EXTENSION, QObject::tr("Extension")},
    {XFileInfoValues::XFIV_ENTROPY, QObject::tr("Entropy")},
    {XFileInfoValues::XFIV_HEADER_BYTES, QObject::tr("Header bytes")},
    {XFileInfoValues::XFIV_ENTRYPOINT_BYTES, QObject::tr("Entry point bytes")},
    {XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE, QObject::tr("Entry point signature")},
    {XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE_RELATIVE, QObject::tr("Entry point signature relative")},
    {XFileInfoValues::XFIV_OVERLAY_BYTES, QObject::tr("Overlay bytes")},
    {XFileInfoValues::XFIV_OVERLAY_SIZE, QObject::tr("Overlay size")},
    {XFileInfoValues::XFIV_OVERLAY_ENTROPY, QObject::tr("Overlay entropy")},
};

const qint32 N_XFIV = sizeof(_TABLE_XFIV) / sizeof(XBinary::XIDSTRING);

bool XFileInfoValues_Sort::operator()(const XFileInfoValues::RecordInfo &recordInfo1, const XFileInfoValues::RecordInfo &recordInfo2) const
{
    if (recordInfo1.bIsDir != recordInfo2.bIsDir) {
        return recordInfo1.bIsDir;
    }

    if ((xFIV == XFileInfoValues::XFIV_SIZE) || (xFIV == XFileInfoValues::XFIV_OVERLAY_SIZE)) {
        qint64 nSize1 = recordInfo1.mapValues.value(xFIV).toLongLong();
        qint64 nSize2 = recordInfo2.mapValues.value(xFIV).toLongLong();

        if (nSize1 != nSize2) {
            return (sortOrder == Qt::DescendingOrder) ? (nSize2 < nSize1) : (nSize1 < nSize2);
        }
    } else if (xFIV == XFileInfoValues::XFIV_EXTENSION) {
        QString sExtension1 = recordInfo1.mapValues.value(XFileInfoValues::XFIV_EXTENSION).toString().toCaseFolded();
        QString sExtension2 = recordInfo2.mapValues.value(XFileInfoValues::XFIV_EXTENSION).toString().toCaseFolded();

        if (sExtension1 != sExtension2) {
            return (sortOrder == Qt::DescendingOrder) ? (sExtension2 < sExtension1) : (sExtension1 < sExtension2);
        }
    } else if ((xFIV == XFileInfoValues::XFIV_ENTROPY) || (xFIV == XFileInfoValues::XFIV_OVERLAY_ENTROPY)) {
        double dEntropy1 = recordInfo1.mapValues.value(xFIV).toDouble();
        double dEntropy2 = recordInfo2.mapValues.value(xFIV).toDouble();

        if (dEntropy1 != dEntropy2) {
            return (sortOrder == Qt::DescendingOrder) ? (dEntropy2 < dEntropy1) : (dEntropy1 < dEntropy2);
        }
    } else if ((xFIV == XFileInfoValues::XFIV_HEADER_BYTES) || (xFIV == XFileInfoValues::XFIV_ENTRYPOINT_BYTES) || (xFIV == XFileInfoValues::XFIV_OVERLAY_BYTES) ||
               (xFIV == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE) || (xFIV == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE_RELATIVE)) {
        QString sValue1 = recordInfo1.mapValues.value(xFIV).toString();
        QString sValue2 = recordInfo2.mapValues.value(xFIV).toString();

        if (sValue1 != sValue2) {
            return (sortOrder == Qt::DescendingOrder) ? (sValue2 < sValue1) : (sValue1 < sValue2);
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

QString XFileInfoValues::valueIdToString(XFIV value)
{
    return XBinary::XIDSTRING_idToString(static_cast<quint64>(value), _TABLE_XFIV, N_XFIV);
}

XFileInfoValues::XFIV XFileInfoValues::valueStringToId(const QString &sValue)
{
    QString _sValue = sValue.toUpper().remove(" ").remove("-");

    return static_cast<XFileInfoValues::XFIV>(XBinary::XIDSTRING_ftStringToId(_sValue, _TABLE_XFIV, N_XFIV));
}

QVariant XFileInfoValues::getDisplayRole(QVariant varValue, XFIV value)
{
    QVariant result = varValue;

    if (varValue.isValid()) {
        if ((value == XFIV_SIZE) || (value == XFIV_OVERLAY_SIZE)) {
            result = XBinary::bytesCountToString(varValue.toLongLong(), 1024);
        } else if ((value == XFIV_ENTROPY) || (value == XFIV_OVERLAY_ENTROPY)) {
            result = QString::number(varValue.toDouble(), 'f', 4);
        }
    }

    return result;
}

Qt::AlignmentFlag XFileInfoValues::getTextAlignmentRole(XFIV value)
{
    Qt::AlignmentFlag result = static_cast<Qt::AlignmentFlag>(0);

    if ((value == XFIV_SIZE) || (value == XFIV_ENTROPY) || (value == XFIV_OVERLAY_SIZE) || (value == XFIV_OVERLAY_ENTROPY)) {
        result = static_cast<Qt::AlignmentFlag>(static_cast<int>(Qt::AlignRight | Qt::AlignVCenter));
    }

    return result;
}

#ifdef QT_WIDGETS_LIB
QList<XComboBoxEx::CUSTOM_FLAG> XFileInfoValues::getColumnCustomFlags()
{
    QList<XComboBoxEx::CUSTOM_FLAG> listResult;

    for (qint32 i = 0; i < N_XFIV; i++) {
        XFIV value = static_cast<XFIV>(_TABLE_XFIV[i].nID);
        bool bChecked = ((value == XFIV_NAME) || (value == XFIV_SIZE) || (value == XFIV_EXTENSION));
        bool bReadonly = (value == XFIV_NAME);

        XComboBoxEx::_addCustomFlag(&listResult, value, valueIdToString(value), bChecked, bReadonly);
    }

    return listResult;
}
#endif

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
    XBinary::_MEMORY_MAP memoryMap = {};
    XBinary *pBinary = nullptr;

    qint32 nNumberOfValues = pList->size();

    for (qint32 i = 0; (i < nNumberOfValues) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XFIV value = pList->at(i);

        if (isBinaryValue(value)) {
            XBinary::FT fileType = XFormats::getPrefFileType(pDevice, true, pPdStruct);
            pBinary = XFormats::getClass(fileType, pDevice, false, -1);
            if (pBinary) {
                memoryMap = pBinary->getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
            }
            break;
        }
    }

    for (qint32 i = 0; (i < nNumberOfValues) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XFIV value = pList->at(i);

        QVariant varValue;

        if (value == XFIV_SIZE) {
            varValue = XBinary::getSize(pDevice);
        } else if (value == XFIV_EXTENSION) {
            varValue = XBinary::getDeviceFileSuffix(pDevice);
        } else if (value == XFIV_ENTROPY) {
            varValue = XBinary::getEntropy(pDevice, pPdStruct);
        } else if (value == XFIV_HEADER_BYTES) {
            varValue = pBinary ? pBinary->getSignature(0, 20) : QString();
        } else if (value == XFIV_ENTRYPOINT_BYTES) {
            varValue = pBinary ? pBinary->getSignature(pBinary->getEntryPointOffset(&memoryMap), 20) : QString();
        } else if (value == XFIV_OVERLAY_BYTES) {
            if (pBinary && pBinary->isOverlayPresent(&memoryMap, pPdStruct)) {
                varValue = pBinary->getSignature(pBinary->getOverlayOffset(), 20);
            }
        } else if ((value == XFIV_ENTRYPOINT_SIGNATURE) || (value == XFIV_ENTRYPOINT_SIGNATURE_RELATIVE)) {
            if (pBinary) {
                XDisasmCore disasmCore;
                disasmCore.setMode(XBinary::getDisasmMode(&memoryMap));

                XDisasmCore::ST signatureType = (value == XFIV_ENTRYPOINT_SIGNATURE_RELATIVE) ? XDisasmCore::ST_REL : XDisasmCore::ST_MASK;
                varValue = disasmCore.getSignature(pDevice, &memoryMap, memoryMap.nEntryPointAddress, signatureType, N_XFIV_SIGNATURECOUNT);
            }
        } else if (value == XFIV_OVERLAY_SIZE) {
            varValue = pBinary ? XBinary::getOverlaySize(&memoryMap, pPdStruct) : 0;
        } else if (value == XFIV_OVERLAY_ENTROPY) {
            if (pBinary && pBinary->isOverlayPresent(&memoryMap, pPdStruct)) {
                qint64 nOverlayOffset = XBinary::getOverlayOffset(&memoryMap, pPdStruct);
                qint64 nOverlaySize = XBinary::getOverlaySize(&memoryMap, pPdStruct);

                varValue = pBinary->getBinaryStatus(XBinary::BSTATUS_ENTROPY, nOverlayOffset, nOverlaySize, pPdStruct);
            }
        }

        result.insert(value, varValue);
    }

    if (pBinary) {
        delete pBinary;
    }

    return result;
}
