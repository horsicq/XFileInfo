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
#include "xfileinfo.h"

XFileInfo::XFileInfo(QObject *pParent) : QObject(pParent)
{
    g_pDevice=nullptr;
    g_bIsStop=false;
}

void XFileInfo::setData(QIODevice *pDevice, QStandardItemModel *pModel, OPTIONS options)
{
    // TODO XBinary for Hash Stop
    this->g_pDevice=pDevice;
    this->g_pModel=pModel;
    this->g_options=options;
}

QString XFileInfo::toXML(QStandardItemModel *pModel)
{
    QString sResult;
    QXmlStreamWriter xml(&sResult);

    xml.setAutoFormatting(true);

    _toXML(&xml,pModel->invisibleRootItem(),0);

    return sResult;
}

QString XFileInfo::toJSON(QStandardItemModel *pModel)
{
    QString sResult;

    QJsonObject jsonResult;

    _toJSON(&jsonResult,pModel->invisibleRootItem(),0);

    QJsonDocument saveFormat(jsonResult);

    QByteArray baData=saveFormat.toJson(QJsonDocument::Indented);

    sResult=baData.data();

    return sResult;
}

QString XFileInfo::toCSV(QStandardItemModel *pModel)
{
    QString sResult;

    _toCSV(&sResult,pModel->invisibleRootItem(),0);

    return sResult;
}

QString XFileInfo::toTSV(QStandardItemModel *pModel)
{
    QString sResult;

    _toTSV(&sResult,pModel->invisibleRootItem(),0);

    return sResult;
}

QString XFileInfo::toFormattedString(QStandardItemModel *pModel)
{
    QString sResult;

    _toFormattedString(&sResult,pModel->invisibleRootItem(),0);

    return sResult;
}

QStandardItem *XFileInfo::appendRecord(QStandardItem *pParent, QString sName, QVariant varData)
{
    QStandardItem *pResult=0;

    pResult=new QStandardItem(sName);
    pResult->setData(varData);

    if(pParent)
    {
        pParent->appendRow(pResult);
    }
    else
    {
        g_pModel->appendRow(pResult);
    }

    return pResult;
}

void XFileInfo::setCurrentStatus(QString sStatus)
{
    g_sCurrentStatus=sStatus;
}

void XFileInfo::_toXML(QXmlStreamWriter *pXml, QStandardItem *pItem, qint32 nLevel)
{
    if(nLevel)
    {
        pXml->writeStartElement("record");
        pXml->writeAttribute("name",pItem->text());
        pXml->writeAttribute("value",pItem->data().toString());
    }
    else
    {
        pXml->writeStartElement("info");
    }

    qint32 nNumberOfChildren=pItem->rowCount();

    for(qint32 i=0;i<nNumberOfChildren;i++)
    {
        _toXML(pXml,pItem->child(i),nLevel+1);
    }

    pXml->writeEndElement();
}

void XFileInfo::_toJSON(QJsonObject *pJsonObject, QStandardItem *pItem, qint32 nLevel)
{
    if(nLevel)
    {
        pJsonObject->insert(pItem->text(),pItem->data().toString());
    }

    if(pItem->rowCount())
    {
        if(nLevel)
        {
            QJsonArray jsArray;

            qint32 nNumberOfChildren=pItem->rowCount();

            for(qint32 i=0;i<nNumberOfChildren;i++)
            {
                QJsonObject jsRecord;

                _toJSON(&jsRecord,pItem->child(i),nLevel+1);

                jsArray.append(jsRecord);
            }

            pJsonObject->insert("records",jsArray);
        }
        else
        {
            qint32 nNumberOfChildren=pItem->rowCount();

            for(qint32 i=0;i<nNumberOfChildren;i++)
            {
                _toJSON(pJsonObject,pItem->child(i),nLevel+1);
            }
        }
    }
}

void XFileInfo::_toCSV(QString *pString, QStandardItem *pItem, qint32 nLevel)
{
    if(nLevel)
    {
        pString->append(QString("%1;%2\n").arg(pItem->text(),pItem->data().toString()));
    }

    qint32 nNumberOfChildren=pItem->rowCount();

    for(qint32 i=0;i<nNumberOfChildren;i++)
    {
        _toCSV(pString,pItem->child(i),nLevel+1);
    }
}

void XFileInfo::_toTSV(QString *pString, QStandardItem *pItem, qint32 nLevel)
{
    if(nLevel)
    {
        pString->append(QString("%1\t%2\n").arg(pItem->text(),pItem->data().toString()));
    }

    qint32 nNumberOfChildren=pItem->rowCount();

    for(qint32 i=0;i<nNumberOfChildren;i++)
    {
        _toTSV(pString,pItem->child(i),nLevel+1);
    }
}

void XFileInfo::_toFormattedString(QString *pString, QStandardItem *pItem, qint32 nLevel)
{
    if(nLevel)
    {
        QString sResult;
        sResult=sResult.leftJustified(4*(nLevel-1),' '); // TODO function
        sResult.append(QString("%1: %2\n").arg(pItem->text(),pItem->data().toString()));
        pString->append(sResult);
    }

    qint32 nNumberOfChildren=pItem->rowCount();

    for(qint32 i=0;i<nNumberOfChildren;i++)
    {
        _toFormattedString(pString,pItem->child(i),nLevel+1);
    }
}

void XFileInfo::stop()
{
    g_bIsStop=true;
}

void XFileInfo::process()
{
    QElapsedTimer scanTimer;
    scanTimer.start();

    appendRecord(0,tr("File name"),XBinary::getDeviceFileName(g_pDevice));

    if(!g_bIsStop)
    {
        setCurrentStatus(tr("Hash"));

        if(g_options.bShowAll)
        {
            if(!g_bIsStop) appendRecord(0,"MD4",XBinary::getHash(XBinary::HASH_MD4,g_pDevice));
        }

        if(!g_bIsStop) appendRecord(0,"MD5",XBinary::getHash(XBinary::HASH_MD5,g_pDevice));
        if(!g_bIsStop) appendRecord(0,"SHA1",XBinary::getHash(XBinary::HASH_SHA1,g_pDevice));

        if(g_options.bShowAll)
        {
            if(!g_bIsStop) appendRecord(0,"SHA224",XBinary::getHash(XBinary::HASH_SHA224,g_pDevice));
            if(!g_bIsStop) appendRecord(0,"SHA256",XBinary::getHash(XBinary::HASH_SHA256,g_pDevice));
            if(!g_bIsStop) appendRecord(0,"SHA384",XBinary::getHash(XBinary::HASH_SHA384,g_pDevice));
            if(!g_bIsStop) appendRecord(0,"SHA512",XBinary::getHash(XBinary::HASH_SHA512,g_pDevice));
        }
    }

    g_bIsStop=false;

    emit completed(scanTimer.elapsed());
}

QString XFileInfo::getCurrentStatus()
{
    return g_sCurrentStatus;
}

