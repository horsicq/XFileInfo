/* Copyright (c) 2021-2023 hors<horsicq@gmail.com>
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
#ifndef XFILEINFO_H
#define XFILEINFO_H

#include "xcapstone.h"
#include "xfileinfomodel.h"
#include "xformats.h"

class XFileInfo : public QObject {
    Q_OBJECT

public:
    struct OPTIONS {
        XBinary::FT fileType;
        //        bool bShowAll;
        bool bComment;
        QString sString;
    };

    struct METHOD {
        QString sTranslated;
        QString sName;
    };

    explicit XFileInfo(QObject *pParent = nullptr);

    void setData(QIODevice *pDevice, XFileInfoModel *pModel, OPTIONS options, XBinary::PDSTRUCT *pPdStruct);
    static bool processFile(const QString &sFileName, XFileInfoModel *pModel, OPTIONS options);
    static QList<METHOD> getMethodNames(XBinary::FT fileType);

signals:
    void errorMessage(QString sText);
    void completed(qint64 nElapsed);

private:
    XFileInfoItem *appendRecord(XFileInfoItem *pItemParent, const QString &sName, QVariant varData);
    void setCurrentStatus(const QString &sStatus);
    bool check(QString sString, QString sExtra);
    QString addFlags(XBinary::MODE mode, quint64 nValue, QMap<quint64, QString> mapFlags, XBinary::VL_TYPE vlType);
    QString addDateTime(XBinary::MODE mode, XBinary::DT_TYPE dtType, quint64 nValue);
    static void _addMethod(QList<METHOD> *pListMethods, QString sTranslated, QString sName);

public slots:
    void process();

private:
    const int N_SIGNATURECOUNT = 10;  // TODO Set/Get
    QIODevice *g_pDevice;
    XFileInfoModel *g_pModel;
    OPTIONS g_options;
    XBinary::PDSTRUCT *g_pPdStruct;
    qint32 g_nFreeIndex;
};

#endif  // XFILEINFO_H
