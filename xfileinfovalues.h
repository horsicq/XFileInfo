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
#ifdef QT_WIDGETS_LIB
#include "xcomboboxex.h"
#endif

#include <QHash>
#ifdef QT_GUI_LIB
#include <QIcon>
#endif
#include <Qt>
#include <QVariant>

class XOptions;

class XFileInfoValues : public XThreadObject {
    Q_OBJECT

public:
    enum XFIV  {
        XFIV_NAME = 0,
        XFIV_NFD_LINKER,
        XFIV_NFD_COMPILER,
        XFIV_NFD_WRAPPER,
        XFIV_DIE_LINKER,
        XFIV_DIE_COMPILER,
        XFIV_DIE_WRAPPER,
        XFIV_SIZE,
        XFIV_EXTENSION,
        XFIV_FILETYPE,
        XFIV_ENTROPY,
        XFIV_ARCH,
        XFIV_HEADER_BYTES,
        XFIV_ENTRYPOINT_BYTES,
        XFIV_ENTRYPOINT_SIGNATURE,
        XFIV_ENTRYPOINT_SIGNATURE_RELATIVE,
        XFIV_OVERLAY_BYTES,
        XFIV_OVERLAY_SIZE,
        XFIV_OVERLAY_ENTROPY,
        XFIV_PE_TIMEDATESTAMP,
        XFIV_PE_MAJORLINKERVERSION,
        XFIV_PE_MINORLINKERVERSION,
        XFIV_PE_NUMBEROFSECTIONS,
        XFIV_PE_FIRSTSECTION_NAME,
        XFIV_PE_FIRSTSECTION_SIZE,
        XFIV_PE_FIRSTSECTION_ENTROPY,
        XFIV_PE_SECONDSECTION_NAME,
        XFIV_PE_SECONDSECTION_SIZE,
        XFIV_PE_SECONDSECTION_ENTROPY,
        XFIV_PE_THIRDSECTION_NAME,
        XFIV_PE_THIRDSECTION_SIZE,
        XFIV_PE_THIRDSECTION_ENTROPY,
        XFIV_PE_NEXTTOLASTSECTION_NAME,
        XFIV_PE_NEXTTOLASTSECTION_SIZE,
        XFIV_PE_NEXTTOLASTSECTION_ENTROPY,
        XFIV_PE_LASTSECTION_NAME,
        XFIV_PE_LASTSECTION_SIZE,
        XFIV_PE_LASTSECTION_ENTROPY,
        XFIV_PE_FIRSTIMPORT_NAME,
        XFIV_PE_FIRSTIMPORT_NUMBEROFFUNCTIONS,
        XFIV_PE_SECONDIMPORT_NAME,
        XFIV_PE_SECONDIMPORT_NUMBEROFFUNCTIONS,
        XFIV_PE_THIRDIMPORT_NAME,
        XFIV_PE_THIRDIMPORT_NUMBEROFFUNCTIONS,
        XFIV_PE_NEXTTOLASTIMPORT_NAME,
        XFIV_PE_NEXTTOLASTIMPORT_NUMBEROFFUNCTIONS,
        XFIV_PE_LASTIMPORT_NAME,
        XFIV_PE_LASTIMPORT_NUMBEROFFUNCTIONS,
        XFIV_PE_IMPORT_HASH32,
        XFIV_PE_IMPORT_HASH64,
        XFIV_PE_EXPORT,
        XFIV_PE_IMPORT,
        XFIV_PE_RESOURCE,
        XFIV_PE_EXCEPTION,
        XFIV_PE_SECURITY,
        XFIV_PE_BASERELOC,
        XFIV_PE_DEBUG,
        XFIV_PE_ARCHITECTURE,
        XFIV_PE_GLOBALPTR,
        XFIV_PE_TLS,
        XFIV_PE_LOAD_CONFIG,
        XFIV_PE_BOUND_IMPORT,
        XFIV_PE_IAT,
        XFIV_PE_DELAY_IMPORT,
        XFIV_PE_COM_DESCRIPTOR,
        __XFIV_SIZE
    };

    struct RecordInfo {
        QString sFileName;
        QString sFilePath;
#ifdef QT_GUI_LIB
        QIcon icon;
#endif
        bool bIsDir;
        bool bIsHidden;
        bool bEnabled;
        QHash<XFIV, QVariant> mapValues;
    };

    struct XFIDATA{
        QList<RecordInfo> listRecords;
        QList<XFIV> listFIV;
    };

    explicit XFileInfoValues(QObject *pParent = nullptr);

    void setData(XFIDATA *pData, XBinary::PDSTRUCT *pPdStruct = nullptr, XOptions *pOptions = nullptr);

    void process() override;
    QString getTitle() override;

    static QString valueIdToString(XFIV value);
    static XFIV valueStringToId(const QString &sValue);
    static QVariant getDisplayRole(QVariant varValue, XFIV value);
    static int getTextAlignmentRole(XFIV value);
#ifdef QT_WIDGETS_LIB
    static QList<XComboBoxEx::CUSTOM_FLAG> getColumnCustomFlags();
#endif
    static QHash<XFIV, QVariant> getValues(const QString &sFileName, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct, XOptions *pOptions = nullptr);
    static QHash<XFIV, QVariant> getValues(QIODevice *pDevice, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct, XOptions *pOptions = nullptr);

private:
    XFIDATA *m_pData;
    XBinary::PDSTRUCT *m_pPdStruct;
    XOptions *m_pOptions;
};

struct XFileInfoValues_Sort {
    Qt::SortOrder sortOrder = Qt::AscendingOrder;
    XFileInfoValues::XFIV xFIV = XFileInfoValues::XFIV_NAME;

    bool operator()(const XFileInfoValues::RecordInfo &recordInfo1, const XFileInfoValues::RecordInfo &recordInfo2) const;
};

#endif  // XFILEINFOVALUES_H
