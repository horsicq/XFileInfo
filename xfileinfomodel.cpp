/* Copyright (c) 2021-2022 hors<horsicq@gmail.com>
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
#include "xfileinfomodel.h"

XFileInfoModel::XFileInfoModel(QObject *pParent) : QAbstractItemModel(pParent) {
    g_pRootItem = new XFileInfoItem("data", "");
}

XFileInfoModel::~XFileInfoModel() {
    delete g_pRootItem;
}

QVariant XFileInfoModel::headerData(int nSection, Qt::Orientation orientation, int nRole) const {
    QVariant result;

    if ((orientation == Qt::Horizontal) && (nRole == Qt::DisplayRole)) {
        result = g_pRootItem->data(nSection);
    }

    return result;
}

QModelIndex XFileInfoModel::index(int nRow, int nColumn, const QModelIndex &parent) const {
    QModelIndex result;

    if (hasIndex(nRow, nColumn, parent)) {
        XFileInfoItem *pItemParent = nullptr;

        if (!parent.isValid()) {
            pItemParent = g_pRootItem;
        } else {
            pItemParent = static_cast<XFileInfoItem *>(parent.internalPointer());
        }

        XFileInfoItem *pItemChild = pItemParent->child(nRow);

        if (pItemChild) {
            result = createIndex(nRow, nColumn, pItemChild);
        }
    }

    return result;
}

QModelIndex XFileInfoModel::parent(const QModelIndex &index) const {
    QModelIndex result;

    if (index.isValid()) {
        XFileInfoItem *pItemChild = static_cast<XFileInfoItem *>(index.internalPointer());
        XFileInfoItem *pParentItem = pItemChild->getParentItem();

        if (pParentItem != g_pRootItem) {
            result = createIndex(pParentItem->row(), 0, pParentItem);
        }
    }

    return result;
}

int XFileInfoModel::rowCount(const QModelIndex &parent) const {
    int nResult = 0;

    if (parent.column() <= 0) {
        XFileInfoItem *pParentItem = nullptr;

        if (!parent.isValid()) {
            pParentItem = g_pRootItem;
        } else {
            pParentItem = static_cast<XFileInfoItem *>(parent.internalPointer());
        }

        nResult = pParentItem->childCount();
    }

    return nResult;
}

int XFileInfoModel::columnCount(const QModelIndex &parent) const {
    int nResult = 0;

    if (parent.isValid()) {
        nResult = static_cast<XFileInfoItem *>(parent.internalPointer())->columnCount();
    } else {
        nResult = g_pRootItem->columnCount();
    }

    return nResult;
}

QVariant XFileInfoModel::data(const QModelIndex &index, int nRole) const {
    QVariant result;

    if (index.isValid()) {
        XFileInfoItem *pItem = static_cast<XFileInfoItem *>(index.internalPointer());

        if (nRole == Qt::DisplayRole) {
            result = pItem->data(index.column());
        }
    }

    return result;
}

Qt::ItemFlags XFileInfoModel::flags(const QModelIndex &index) const {
    Qt::ItemFlags result = Qt::NoItemFlags;

    if (index.isValid()) {
        result = QAbstractItemModel::flags(index);
    }

    return result;
}

void XFileInfoModel::appendChild(XFileInfoItem *pItemChild) {
    g_pRootItem->appendChild(pItemChild);
}

QString XFileInfoModel::toXML() {
    QString sResult;
    QXmlStreamWriter xml(&sResult);

    xml.setAutoFormatting(true);

    _toXML(&xml, g_pRootItem, 0);

    return sResult;
}

QString XFileInfoModel::toJSON() {
    QString sResult;

    QJsonObject jsonResult;

    _toJSON(&jsonResult, g_pRootItem, 0);

    QJsonDocument saveFormat(jsonResult);

    QByteArray baData = saveFormat.toJson(QJsonDocument::Indented);

    sResult = baData.data();

    return sResult;
}

QString XFileInfoModel::toCSV() {
    QString sResult;

    _toCSV(&sResult, g_pRootItem, 0);

    return sResult;
}

QString XFileInfoModel::toTSV() {
    QString sResult;

    _toTSV(&sResult, g_pRootItem, 0);

    return sResult;
}

QString XFileInfoModel::toFormattedString() {
    QString sResult;

    _toFormattedString(&sResult, g_pRootItem, 0);

    return sResult;
}

void XFileInfoModel::_toXML(QXmlStreamWriter *pXml, XFileInfoItem *pItem, qint32 nLevel) {
    if (nLevel) {
        pXml->writeStartElement("record");
        pXml->writeAttribute("name", pItem->getName());

        if (!(pItem->childCount())) {
            pXml->writeAttribute("value", pItem->getValue().toString());
        }
    } else {
        pXml->writeStartElement("data");
    }

    qint32 nNumberOfChildren = pItem->childCount();

    for (qint32 i = 0; i < nNumberOfChildren; i++) {
        _toXML(pXml, pItem->child(i), nLevel + 1);
    }

    pXml->writeEndElement();
}

void XFileInfoModel::_toJSON(QJsonObject *pJsonObject, XFileInfoItem *pItem, qint32 nLevel) {
    //    if(nLevel)
    //    {
    //        pJsonObject->insert(pItem->getName(),pItem->getValue().toString());
    //    }

    //    if(pItem->childCount())
    //    {
    //        if(nLevel)
    //        {
    //            QJsonArray jsArray;

    //            qint32 nNumberOfChildren=pItem->childCount();

    //            for(qint32 i=0;i<nNumberOfChildren;i++)
    //            {
    //                QJsonObject jsRecord;

    //                _toJSON(&jsRecord,pItem->child(i),nLevel+1);

    //                jsArray.append(jsRecord);
    //            }

    //            pJsonObject->insert("records",jsArray);
    //        }
    //        else
    //        {
    //            qint32 nNumberOfChildren=pItem->childCount();

    //            for(qint32 i=0;i<nNumberOfChildren;i++)
    //            {
    //                _toJSON(pJsonObject,pItem->child(i),nLevel+1);
    //            }
    //        }
    //    }
    if (pItem->childCount()) {
        QJsonObject jsObject;

        qint32 nNumberOfChildren = pItem->childCount();

        for (qint32 i = 0; i < nNumberOfChildren; i++) {
            _toJSON(&jsObject, pItem->child(i), nLevel + 1);
        }

        pJsonObject->insert(pItem->getName(), jsObject);
    } else {
        pJsonObject->insert(pItem->getName(), pItem->getValue().toString());
    }
}

void XFileInfoModel::_toCSV(QString *pString, XFileInfoItem *pItem, qint32 nLevel) {
    if (nLevel) {
        pString->append(QString("%1;%2\n").arg(pItem->getName(), pItem->getValue().toString()));
    }

    qint32 nNumberOfChildren = pItem->childCount();

    for (qint32 i = 0; i < nNumberOfChildren; i++) {
        _toCSV(pString, pItem->child(i), nLevel + 1);
    }
}

void XFileInfoModel::_toTSV(QString *pString, XFileInfoItem *pItem, qint32 nLevel) {
    if (nLevel) {
        pString->append(QString("%1\t%2\n").arg(pItem->getName(), pItem->getValue().toString()));
    }

    qint32 nNumberOfChildren = pItem->childCount();

    for (qint32 i = 0; i < nNumberOfChildren; i++) {
        _toTSV(pString, pItem->child(i), nLevel + 1);
    }
}

void XFileInfoModel::_toFormattedString(QString *pString, XFileInfoItem *pItem, qint32 nLevel) {
    if (nLevel) {
        QString sResult;
        sResult = sResult.leftJustified(4 * (nLevel - 1), ' ');  // TODO function
        sResult.append(QString("%1: %2\n").arg(pItem->getName(), pItem->getValue().toString()));
        pString->append(sResult);
    }

    qint32 nNumberOfChildren = pItem->childCount();

    for (qint32 i = 0; i < nNumberOfChildren; i++) {
        _toFormattedString(pString, pItem->child(i), nLevel + 1);
    }
}
