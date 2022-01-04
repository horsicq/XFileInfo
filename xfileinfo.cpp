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
    this->g_pDevice=pDevice;
    this->g_pModel=pModel;
    this->g_options=options;
}

QStandardItem *XFileInfo::appendRecord(QStandardItem *pParent, QString sName, QVariant varData)
{
    QStandardItem *pResult=0;

    bool bSuccess=true;

    if(varData.toString()=="")
    {
        bSuccess=g_options.bShowAll;
    }

    if(bSuccess)
    {
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
    }

    return pResult;
}

void XFileInfo::setCurrentStatus(QString sStatus)
{
    g_sCurrentStatus=sStatus;
}

void XFileInfo::stop()
{
    g_bIsStop=true;
}

void XFileInfo::process()
{
    QElapsedTimer scanTimer;
    scanTimer.start();

    g_pModel=new QStandardItemModel;

    appendRecord(0,tr("File name"),XBinary::getDeviceFileName(g_pDevice));

    g_bIsStop=false;

    emit completed(scanTimer.elapsed());
}

QString XFileInfo::getCurrentStatus()
{
    return g_sCurrentStatus;
}

