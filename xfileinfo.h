/* Copyright (c) 2021 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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

#include <QStandardItem>
#include <QStandardItemModel>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamWriter>
#include "xformats.h"

class XFileInfo : public QObject
{
    Q_OBJECT

public:

    struct OPTIONS
    {
        XBinary::FT fileType;
        bool bShowAll;
        bool bComment;
    };

    explicit XFileInfo(QObject *pParent=nullptr);

    void setData(QIODevice *pDevice,QStandardItemModel *pModel,OPTIONS options);

    static QString toXML(QStandardItemModel *pModel);
    static QString toJSON(QStandardItemModel *pModel);
    static QString toCSV(QStandardItemModel *pModel);
    static QString toTSV(QStandardItemModel *pModel);
    static QString toFormattedString(QStandardItemModel *pModel);

signals:
    void errorMessage(QString sText);
    void completed(qint64 nElapsed);

private:
    QStandardItem *appendRecord(QStandardItem *pParent,QString sName,QVariant varData);
    void setCurrentStatus(QString sStatus);
    static void _toXML(QXmlStreamWriter *pXml,QStandardItem *pItem,qint32 nLevel);
    static void _toJSON(QJsonObject *pJsonObject,QStandardItem *pItem,qint32 nLevel);
    static void _toCSV(QString *pString,QStandardItem *pItem,qint32 nLevel);
    static void _toTSV(QString *pString,QStandardItem *pItem,qint32 nLevel);
    static void _toFormattedString(QString *pString,QStandardItem *pItem,qint32 nLevel);
    void addOsInfo(XBinary::OSINFO osInfo);

public slots:
    void stop();
    void process();
    QString getCurrentStatus();

private:
    QIODevice *g_pDevice;
    QStandardItemModel *g_pModel;
    OPTIONS g_options;
    bool g_bIsStop;
    QString g_sCurrentStatus;
};

#endif // XFILEINFO_H
