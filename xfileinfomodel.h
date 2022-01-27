/* Copyright (c) 2021-2022 hors<horsicq@gmail.com>
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
#ifndef XFILEINFOMODEL_H
#define XFILEINFOMODEL_H

#include <QAbstractItemModel>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QXmlStreamWriter>
#include "xfileinfoitem.h"

class XFileInfoModel : public QAbstractItemModel
{
    Q_OBJECT
public:
    explicit XFileInfoModel(QObject *pParent=nullptr);
    ~XFileInfoModel() override;

    QVariant headerData(int nSection,Qt::Orientation orientation,int nRole=Qt::DisplayRole) const override;
    QModelIndex index(int nRow,int nColumn,const QModelIndex &parent=QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &index) const override;
    int rowCount(const QModelIndex &parent=QModelIndex()) const override;
    int columnCount(const QModelIndex &parent=QModelIndex()) const override;
    QVariant data(const QModelIndex &index,int nRole=Qt::DisplayRole) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;

    void appendChild(XFileInfoItem *pChild);

    QString toXML();
    QString toJSON();
    QString toCSV();
    QString toTSV();
    QString toFormattedString();

private:
    void _toXML(QXmlStreamWriter *pXml,XFileInfoItem *pItem,qint32 nLevel);
    void _toJSON(QJsonObject *pJsonObject,XFileInfoItem *pItem,qint32 nLevel);
    void _toCSV(QString *pString,XFileInfoItem *pItem,qint32 nLevel);
    void _toTSV(QString *pString,XFileInfoItem *pItem,qint32 nLevel);
    void _toFormattedString(QString *pString,XFileInfoItem *pItem,qint32 nLevel);

private:
    XFileInfoItem *g_pRootItem;
};

#endif // XFILEINFOMODEL_H
