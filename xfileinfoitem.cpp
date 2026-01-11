/* Copyright (c) 2021-2026 hors<horsicq@gmail.com>
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
#include "xfileinfoitem.h"

XFileInfoItem::XFileInfoItem(const QString &sName, const QVariant &varValue, XFileInfoItem *pParentItem)
{
    this->m_pParentItem = pParentItem;
    this->m_sName = sName;
    this->m_varValue = varValue;
}

XFileInfoItem::~XFileInfoItem()
{
    qDeleteAll(m_listChildItems);
}

void XFileInfoItem::appendChild(XFileInfoItem *pItemChild)
{
    m_listChildItems.append(pItemChild);
}

XFileInfoItem *XFileInfoItem::child(int nRow)
{
    return m_listChildItems.value(nRow);
}

int XFileInfoItem::childCount() const
{
    return m_listChildItems.count();
}

int XFileInfoItem::columnCount() const
{
    return 1;
}

QVariant XFileInfoItem::data(int nColumn) const
{
    QVariant result;

    if (nColumn == 0) {
        result = m_sName;
    }

    return result;
}

QString XFileInfoItem::getName()
{
    return m_sName;
}

QVariant XFileInfoItem::getValue()
{
    return m_varValue;
}

int XFileInfoItem::row() const
{
    int nResult = 0;

    if (m_pParentItem) {
        nResult = m_pParentItem->m_listChildItems.indexOf(const_cast<XFileInfoItem *>(this));
    }

    return nResult;
}

XFileInfoItem *XFileInfoItem::getParentItem()
{
    return m_pParentItem;
}
