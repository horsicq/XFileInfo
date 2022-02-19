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

void XFileInfo::setData(QIODevice *pDevice,XFileInfoModel *pModel,OPTIONS options)
{
    // TODO XBinary for Hash Stop
    this->g_pDevice=pDevice;
    this->g_pModel=pModel;
    this->g_options=options;
}

bool XFileInfo::processFile(QString sFileName,XFileInfoModel *pModel,OPTIONS options)
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

QList<QString> XFileInfo::getMethodNames(XBinary::FT fileType)
{
    QList<QString> listResult;

    listResult.append("File name");
    listResult.append("Size");
    listResult.append("Hash");
    listResult.append("MD4");
    listResult.append("MD5");
    listResult.append("SHA1");
    listResult.append("SHA224");
    listResult.append("SHA256");
    listResult.append("SHA384");
    listResult.append("SHA512");
    listResult.append("Entropy");
    listResult.append("File type");

    if( XBinary::checkFileType(XBinary::FT_ELF,fileType)||
        XBinary::checkFileType(XBinary::FT_MACHO,fileType)||
        XBinary::checkFileType(XBinary::FT_COM,fileType)||
        XBinary::checkFileType(XBinary::FT_PE,fileType)||
        XBinary::checkFileType(XBinary::FT_NE,fileType)||
        XBinary::checkFileType(XBinary::FT_LE,fileType)||
        XBinary::checkFileType(XBinary::FT_MSDOS,fileType)||
        XBinary::checkFileType(XBinary::FT_DEX,fileType))
    {
        listResult.append("Operation system");
        listResult.append("Architecture");
        listResult.append("Mode");
        listResult.append("Type");
        listResult.append("Endianess");
    }

    if( XBinary::checkFileType(XBinary::FT_ELF,fileType)||
        XBinary::checkFileType(XBinary::FT_MACHO,fileType)||
        XBinary::checkFileType(XBinary::FT_COM,fileType)||
        XBinary::checkFileType(XBinary::FT_PE,fileType)||
        XBinary::checkFileType(XBinary::FT_NE,fileType)||
        XBinary::checkFileType(XBinary::FT_LE,fileType)||
        XBinary::checkFileType(XBinary::FT_MSDOS,fileType))
    {
        listResult.append("Entry point");
        listResult.append("Entry point(Address)");
        listResult.append("Entry point(Offset)");
        listResult.append("Entry point(Relative address)");
        listResult.append("Entry point(Bytes)");
        listResult.append("Entry point(Signature)");
        listResult.append("Entry point(Signature)(Rel)");
    }

    if(XBinary::checkFileType(XBinary::FT_ELF,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_MACHO,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_PE,fileType))
    {
        // TODO
        // Image base
    }
    else if(XBinary::checkFileType(XBinary::FT_NE,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_LE,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_MSDOS,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_DEX,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_COM,fileType))
    {
        // TODO
    }
    else if(XBinary::checkFileType(XBinary::FT_PDF,fileType))
    {
        listResult.append("Version");
    }

    return listResult;
}

XFileInfoItem *XFileInfo::appendRecord(XFileInfoItem *pParent,QString sName,QVariant varData)
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

bool XFileInfo::check(QString sString,QString sExtra)
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
        if(check("MD4","Hash")) appendRecord(0,"MD4",XBinary::getHash(XBinary::HASH_MD4,g_pDevice));
    }

    if(check("MD5","Hash")) appendRecord(0,"MD5",XBinary::getHash(XBinary::HASH_MD5,g_pDevice));
    if(check("SHA1","Hash")) appendRecord(0,"SHA1",XBinary::getHash(XBinary::HASH_SHA1,g_pDevice));

    if((g_options.bShowAll)||(g_options.sString!=""))
    {
        if(check("SHA224","Hash")) appendRecord(0,"SHA224",XBinary::getHash(XBinary::HASH_SHA224,g_pDevice));
        if(check("SHA256","Hash")) appendRecord(0,"SHA256",XBinary::getHash(XBinary::HASH_SHA256,g_pDevice));
        if(check("SHA384","Hash")) appendRecord(0,"SHA384",XBinary::getHash(XBinary::HASH_SHA384,g_pDevice));
        if(check("SHA512","Hash")) appendRecord(0,"SHA512",XBinary::getHash(XBinary::HASH_SHA512,g_pDevice));
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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(elf.getFileType()));

                    XBinary::OSINFO osInfo=elf.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=elf.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(elf.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(elf.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(elf.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(mach.getFileType()));

                    XBinary::OSINFO osInfo=mach.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=mach.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(mach.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(mach.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(mach.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(pe.getFileType()));

                    XBinary::OSINFO osInfo=pe.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=pe.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(pe.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(pe.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(pe.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(ne.getFileType()));

                    XBinary::OSINFO osInfo=ne.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=ne.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(ne.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(ne.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(ne.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(le.getFileType()));

                    XBinary::OSINFO osInfo=le.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=le.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(le.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(le.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(le.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(msdos.getFileType()));

                    XBinary::OSINFO osInfo=msdos.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=msdos.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(msdos.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(msdos.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(msdos.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_COM,fileType))
        {
            XCOM xcom(g_pDevice);

            if(xcom.isValid())
            {
                if(!g_bIsStop)
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(xcom.getFileType()));

                    XBinary::OSINFO osInfo=xcom.getOsInfo();

                    addOsInfo(osInfo);

                    XBinary::_MEMORY_MAP memoryMap=xcom.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(xcom.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(xcom.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(xcom.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

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
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(dex.getFileType()));

                    XBinary::OSINFO osInfo=dex.getOsInfo();

                    addOsInfo(osInfo);

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_PDF,fileType))
        {
            XPDF pdf(g_pDevice);

            if(pdf.isValid())
            {
                if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(pdf.getFileType()));
                if(check("Version","Version")) appendRecord(0,tr("Version"),pdf.getVersion());
            }
        }
        else
        {
            if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(XBinary::getPrefFileType(g_pDevice,true)));
        }
    }

    g_bIsStop=false;

    emit completed(scanTimer.elapsed());
}

QString XFileInfo::getCurrentStatus()
{
    return g_sCurrentStatus;
}

