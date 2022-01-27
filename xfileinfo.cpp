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
#include "xfileinfo.h"

XFileInfo::XFileInfo(QObject *pParent) : QObject(pParent)
{
    g_pDevice=nullptr;
    g_bIsStop=false;
}

void XFileInfo::setData(QIODevice *pDevice, XFileInfoModel *pModel, OPTIONS options)
{
    // TODO XBinary for Hash Stop
    this->g_pDevice=pDevice;
    this->g_pModel=pModel;
    this->g_options=options;
}

bool XFileInfo::processFile(QString sFileName, XFileInfoModel *pModel, OPTIONS options)
{
    bool bResult=false;

    QFile file;

    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadOnly))
    {
        XFileInfo fileInfo;
        fileInfo.setData(&file,pModel,options);
        fileInfo.process();

        file.close();

        bResult=true;
    }

    return bResult;
}

XFileInfoItem *XFileInfo::appendRecord(XFileInfoItem *pParent, QString sName, QVariant varData)
{
    XFileInfoItem *pResult=0;

    pResult=new XFileInfoItem(sName,varData);

    if(pParent)
    {
        pParent->appendChild(pResult);
    }
    else
    {
        g_pModel->appendChild(pResult);
    }

    return pResult;
}

void XFileInfo::setCurrentStatus(QString sStatus)
{
    g_sCurrentStatus=sStatus;
}

void XFileInfo::addOsInfo(XBinary::OSINFO osInfo)
{
    if(check("Operation system",""))
    {
        QString sOperationSystem=XBinary::osNameIdToString(osInfo.osName);

        if(osInfo.sOsVersion!="")
        {
            sOperationSystem+=QString("(%1)").arg(osInfo.sOsVersion);
        }

        appendRecord(0,tr("Operation system"),sOperationSystem);
    }

    if(check("Architecture","")) appendRecord(0,tr("Architecture"),osInfo.sArch);
    if(check("Mode","")) appendRecord(0,tr("Mode"),XBinary::modeIdToString(osInfo.mode));
    if(check("Type","")) appendRecord(0,tr("Type"),osInfo.sType);
    if(check("Endianess","")) appendRecord(0,tr("Endianess"),XBinary::endiannessToString(osInfo.bIsBigEndian));
}

bool XFileInfo::check(QString sString, QString sExtra)
{
    bool bResult=false;

    if(!g_bIsStop)
    {
        if(g_options.sString!="")
        {
            if(g_options.sString==sString)
            {
                bResult=true;
            }
            else if(g_options.sString==sExtra)
            {
                bResult=true;
            }
        }
        else
        {
            bResult=true;
        }
    }

    if(bResult)
    {
        setCurrentStatus(sString);
    }

    return bResult;
}

void XFileInfo::stop()
{
    g_bIsStop=true;
}

void XFileInfo::process()
{
    QElapsedTimer scanTimer;
    scanTimer.start();

    XBinary::FT fileType=g_options.fileType;

    if(fileType==XBinary::FT_UNKNOWN)
    {
        fileType=XBinary::getPrefFileType(g_pDevice);
    }

    if(check("File name","")) appendRecord(0,tr("File name"),XBinary::getDeviceFileName(g_pDevice));

    qint64 nSize=g_pDevice->size();
    QString sSize=QString::number(nSize);

    if(g_options.bComment)
    {
        sSize+=QString("(%1)").arg(XBinary::bytesCountToString(nSize));
    }

    if(check("Size","")) appendRecord(0,tr("Size"),sSize);

    if((g_options.bShowAll)||(g_options.sString!=""))
    {
        if(check("MD4","hash")) appendRecord(0,"MD4",XBinary::getHash(XBinary::HASH_MD4,g_pDevice));
    }

    if(check("MD5","hash")) appendRecord(0,"MD5",XBinary::getHash(XBinary::HASH_MD5,g_pDevice));
    if(check("SHA1","hash")) appendRecord(0,"SHA1",XBinary::getHash(XBinary::HASH_SHA1,g_pDevice));

    if((g_options.bShowAll)||(g_options.sString!=""))
    {
        if(check("SHA224","hash")) appendRecord(0,"SHA224",XBinary::getHash(XBinary::HASH_SHA224,g_pDevice));
        if(check("SHA256","hash")) appendRecord(0,"SHA256",XBinary::getHash(XBinary::HASH_SHA256,g_pDevice));
        if(check("SHA384","hash")) appendRecord(0,"SHA384",XBinary::getHash(XBinary::HASH_SHA384,g_pDevice));
        if(check("SHA512","hash")) appendRecord(0,"SHA512",XBinary::getHash(XBinary::HASH_SHA512,g_pDevice));
    }

    if(check("Entropy",""))
    {
        double dEntropy=XBinary::getEntropy(g_pDevice);
        QString sEntropy=QString::number(dEntropy);

        if(g_options.bComment)
        {
            sEntropy+=QString("(%1)").arg(XBinary::isPacked(dEntropy)?(tr("packed")):(tr("not packed")));
        }

        appendRecord(0,tr("Entropy"),sEntropy);
    }

    if(!g_bIsStop)
    {
        if(XBinary::checkFileType(XBinary::FT_ELF,fileType))
        {
            XELF elf(g_pDevice);

            if(elf.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=elf.getOsInfo();

                    addOsInfo(osInfo);

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_MACHO,fileType))
        {
            XMACH mach(g_pDevice);

            if(mach.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=mach.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=mach.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(mach.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(mach.getEntryPointOffset(&memoryMap)));

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_PE,fileType))
        {
            XPE pe(g_pDevice);

            if(pe.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=pe.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=pe.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(pe.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(pe.getEntryPointOffset(&memoryMap)));

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_NE,fileType))
        {
            XNE ne(g_pDevice);

            if(ne.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=ne.getOsInfo();

                    addOsInfo(osInfo);

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_LE,fileType))
        {
            XLE le(g_pDevice);

            if(le.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=le.getOsInfo();

                    addOsInfo(osInfo);

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_MSDOS,fileType))
        {
            XMSDOS msdos(g_pDevice);

            if(msdos.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=msdos.getOsInfo();

                    addOsInfo(osInfo);

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_DEX,fileType))
        {
            XDEX dex(g_pDevice);

            if(dex.isValid())
            {
                if(!g_bIsStop)
                {
                    XBinary::OSINFO osInfo=dex.getOsInfo();

                    addOsInfo(osInfo);

                    // TODO
                }
            }
        }
    }

    g_bIsStop=false;

    emit completed(scanTimer.elapsed());
}

QString XFileInfo::getCurrentStatus()
{
    return g_sCurrentStatus;
}

