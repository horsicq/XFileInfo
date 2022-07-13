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
    g_options={};
}

void XFileInfo::setData(QIODevice *pDevice,XFileInfoModel *pModel,OPTIONS options,XBinary::PDSTRUCT *pPdStruct)
{
    // mb TODO XBinary for Hash Stop
    this->g_pDevice=pDevice;
    this->g_pModel=pModel;
    this->g_options=options;
    this->g_pPdStruct=pPdStruct;
}

bool XFileInfo::processFile(QString sFileName,XFileInfoModel *pModel,OPTIONS options)
{
    bool bResult=false;

    QFile file;

    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadOnly))
    {
        XFileInfo fileInfo;
        XBinary::PDSTRUCT pdStruct={};
        fileInfo.setData(&file,pModel,options,&pdStruct);
        fileInfo.process();

        file.close();

        bResult=true;
    }

    return bResult;
}

QList<QString> XFileInfo::getMethodNames(XBinary::FT fileType)
{
    QList<QString> listResult;

    listResult.append("Info");
    listResult.append("Hash");
    listResult.append("Entropy");

    if( XBinary::checkFileType(XBinary::FT_ELF,fileType)||
        XBinary::checkFileType(XBinary::FT_MACHO,fileType)||
        XBinary::checkFileType(XBinary::FT_COM,fileType)||
        XBinary::checkFileType(XBinary::FT_PE,fileType)||
        XBinary::checkFileType(XBinary::FT_NE,fileType)||
        XBinary::checkFileType(XBinary::FT_LE,fileType)||
        XBinary::checkFileType(XBinary::FT_MSDOS,fileType))
    {
        listResult.append("Entry point");
    }

    if(XBinary::checkFileType(XBinary::FT_ELF,fileType))
    {
        listResult.append("ident");
        listResult.append("ehdr");
    }
    else if(XBinary::checkFileType(XBinary::FT_MACHO,fileType))
    {
        listResult.append("header");
    }
    else if(XBinary::checkFileType(XBinary::FT_MACHOFAT,fileType))
    {
        // TODO !!!
        // Header
        // Archs
    }
    else if(XBinary::checkFileType(XBinary::FT_PE,fileType))
    {
        listResult.append("IMAGE_FILE_HEADER");
        listResult.append("IMAGE_OPTIONAL_HEADER");

        //TODO
        // TODO
        // Image base
    }
    else if(XBinary::checkFileType(XBinary::FT_NE,fileType))
    {
        // TODO !!!
    }
    else if(XBinary::checkFileType(XBinary::FT_LE,fileType))
    {
        // TODO !!!
    }
    else if(XBinary::checkFileType(XBinary::FT_MSDOS,fileType))
    {
        listResult.append("IMAGE_DOS_HEADER");
    }
    else if(XBinary::checkFileType(XBinary::FT_DEX,fileType))
    {
        listResult.append("Header");
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
    g_pPdStruct->pdRecordOpt.sStatus=sStatus;
}

bool XFileInfo::check(QString sString, QString sExtra)
{
    bool bResult=false;

    if(!(g_pPdStruct->bIsStop))
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

    if(bResult)
    {
        setCurrentStatus(sString);
    }

    return bResult;
}

QString XFileInfo::addFlags(XBinary::MODE mode,quint64 nValue,QMap<quint64,QString> mapFlags,XBinary::VL_TYPE vlType)
{
    QString sResult=XBinary::valueToHex(mode,nValue);

    if(g_options.bComment)
    {
        sResult+=QString("(%1)").arg(XBinary::valueToFlagsString(nValue,mapFlags,vlType));
    }

    return sResult;
}

QString XFileInfo::addDateTime(XBinary::MODE mode,XBinary::DT_TYPE dtType,quint64 nValue)
{
    QString sResult=XBinary::valueToHex(mode,nValue);

    if(g_options.bComment)
    {
        sResult+=QString("(%1)").arg(XBinary::valueToTimeString(nValue,dtType));
    }

    return sResult;
}

void XFileInfo::process()
{
    QElapsedTimer scanTimer;
    scanTimer.start();

    g_pPdStruct->pdRecordOpt.bIsValid=true;

    XBinary::FT fileType=g_options.fileType;

    if(fileType==XBinary::FT_UNKNOWN)
    {
        fileType=XBinary::getPrefFileType(g_pDevice);
    }

    if(check("Info","All"))
    {
        XFileInfoItem *pParent=appendRecord(0,tr("Info"),"");

        appendRecord(pParent,tr("File name"),XBinary::getDeviceFileName(g_pDevice));

        qint64 nSize=g_pDevice->size();
        QString sSize=QString::number(nSize);

        if(g_options.bComment)
        {
            sSize+=QString("(%1)").arg(XBinary::bytesCountToString(nSize));
        }

        appendRecord(pParent,tr("Size"),sSize);

        if( XBinary::checkFileType(XBinary::FT_ELF,fileType)||
            XBinary::checkFileType(XBinary::FT_PE,fileType))
        {
            XBinary::OSINFO osInfo=XFormats::getOsInfo(fileType,g_pDevice);

            QString sOperationSystem=XBinary::osNameIdToString(osInfo.osName);

            if(osInfo.sOsVersion!="")
            {
                sOperationSystem+=QString("(%1)").arg(osInfo.sOsVersion);
            }

            appendRecord(pParent,tr("Operation system"),sOperationSystem);

            appendRecord(pParent,tr("Architecture"),osInfo.sArch);
            appendRecord(pParent,tr("Mode"),XBinary::modeIdToString(osInfo.mode));
            appendRecord(pParent,tr("Type"),osInfo.sType);
            appendRecord(pParent,tr("Endianness"),XBinary::endiannessToString(osInfo.bIsBigEndian));
        }
    }

    if(check("Hash","All"))
    {
        XFileInfoItem *pParent=appendRecord(0,tr("Hash"),"");

        appendRecord(pParent,"MD4",XBinary::getHash(XBinary::HASH_MD4,g_pDevice,g_pPdStruct));
        appendRecord(pParent,"MD5",XBinary::getHash(XBinary::HASH_MD5,g_pDevice,g_pPdStruct));
        appendRecord(pParent,"SHA1",XBinary::getHash(XBinary::HASH_SHA1,g_pDevice,g_pPdStruct));
        appendRecord(pParent,"SHA224",XBinary::getHash(XBinary::HASH_SHA224,g_pDevice,g_pPdStruct));
        appendRecord(pParent,"SHA256",XBinary::getHash(XBinary::HASH_SHA256,g_pDevice,g_pPdStruct));
        appendRecord(pParent,"SHA384",XBinary::getHash(XBinary::HASH_SHA384,g_pDevice,g_pPdStruct));
        appendRecord(pParent,"SHA512",XBinary::getHash(XBinary::HASH_SHA512,g_pDevice,g_pPdStruct));
    }

    if(check("Entropy","All"))
    {
        double dEntropy=XBinary::getEntropy(g_pDevice,g_pPdStruct);
        QString sEntropy=QString::number(dEntropy);

        if(g_options.bComment)
        {
            sEntropy+=QString("(%1)").arg(XBinary::isPacked(dEntropy)?(tr("packed")):(tr("not packed")));
        }

        appendRecord(0,tr("Entropy"),sEntropy);
    }

    if(!(g_pPdStruct->bIsStop))
    {
        if(XBinary::checkFileType(XBinary::FT_BINARY,fileType))
        {
            XBinary binary(g_pDevice);

            if(binary.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(binary.getFileType()));
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_ELF,fileType))
        {
            XELF elf(g_pDevice);

            if(elf.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    bool bIs64=elf.is64();

                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(elf.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap=elf.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(elf.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(elf.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(elf.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

                    if(check("ident_mag","ident"))                          appendRecord(0,"ident_mag",XBinary::valueToHex(elf.getIdent_mag_LE()));
                    if(check("ident_class","ident"))                        appendRecord(0,"ident_class",XBinary::valueToHex(elf.getIdent_class()));
                    if(check("ident_data","ident"))                         appendRecord(0,"ident_data",XBinary::valueToHex(elf.getIdent_data()));
                    if(check("ident_version","ident"))                      appendRecord(0,"ident_version",XBinary::valueToHex(elf.getIdent_version()));
                    if(check("ident_osabi","ident"))                        appendRecord(0,"ident_osabi",XBinary::valueToHex(elf.getIdent_osabi()));
                    if(check("ident_abiversion","ident"))                   appendRecord(0,"ident_abiversion",XBinary::valueToHex(elf.getIdent_abiversion()));

                    if(bIs64)
                    {
                        if(check("type","ehdr"))                            appendRecord(0,"type",XBinary::valueToHex(elf.getHdr64_type()));
                        if(check("machine","ehdr"))                         appendRecord(0,"machine",XBinary::valueToHex(elf.getHdr64_machine()));
                        if(check("version","ehdr"))                         appendRecord(0,"version",XBinary::valueToHex(elf.getHdr64_version()));
                        if(check("entry","ehdr"))                           appendRecord(0,"entry",XBinary::valueToHex(elf.getHdr64_entry()));
                        if(check("phoff","ehdr"))                           appendRecord(0,"phoff",XBinary::valueToHex(elf.getHdr64_phoff()));
                        if(check("shoff","ehdr"))                           appendRecord(0,"shoff",XBinary::valueToHex(elf.getHdr64_shoff()));
                        if(check("flags","ehdr"))                           appendRecord(0,"flags",XBinary::valueToHex(elf.getHdr64_flags()));
                        if(check("ehsize","ehdr"))                          appendRecord(0,"ehsize",XBinary::valueToHex(elf.getHdr64_ehsize()));
                        if(check("phentsize","ehdr"))                       appendRecord(0,"phentsize",XBinary::valueToHex(elf.getHdr64_phentsize()));
                        if(check("phnum","ehdr"))                           appendRecord(0,"phnum",XBinary::valueToHex(elf.getHdr64_phnum()));
                        if(check("shentsize","ehdr"))                       appendRecord(0,"shentsize",XBinary::valueToHex(elf.getHdr64_shentsize()));
                        if(check("shnum","ehdr"))                           appendRecord(0,"shnum",XBinary::valueToHex(elf.getHdr64_shnum()));
                        if(check("shstrndx","ehdr"))                        appendRecord(0,"shstrndx",XBinary::valueToHex(elf.getHdr64_shstrndx()));
                    }
                    else
                    {
                        if(check("type","ehdr"))                            appendRecord(0,"type",XBinary::valueToHex(elf.getHdr32_type()));
                        if(check("machine","ehdr"))                         appendRecord(0,"machine",XBinary::valueToHex(elf.getHdr32_machine()));
                        if(check("version","ehdr"))                         appendRecord(0,"version",XBinary::valueToHex(elf.getHdr32_version()));
                        if(check("entry","ehdr"))                           appendRecord(0,"entry",XBinary::valueToHex(elf.getHdr32_entry()));
                        if(check("phoff","ehdr"))                           appendRecord(0,"phoff",XBinary::valueToHex(elf.getHdr32_phoff()));
                        if(check("shoff","ehdr"))                           appendRecord(0,"shoff",XBinary::valueToHex(elf.getHdr32_shoff()));
                        if(check("flags","ehdr"))                           appendRecord(0,"flags",XBinary::valueToHex(elf.getHdr32_flags()));
                        if(check("ehsize","ehdr"))                          appendRecord(0,"ehsize",XBinary::valueToHex(elf.getHdr32_ehsize()));
                        if(check("phentsize","ehdr"))                       appendRecord(0,"phentsize",XBinary::valueToHex(elf.getHdr32_phentsize()));
                        if(check("phnum","ehdr"))                           appendRecord(0,"phnum",XBinary::valueToHex(elf.getHdr32_phnum()));
                        if(check("shentsize","ehdr"))                       appendRecord(0,"shentsize",XBinary::valueToHex(elf.getHdr32_shentsize()));
                        if(check("shnum","ehdr"))                           appendRecord(0,"shnum",XBinary::valueToHex(elf.getHdr32_shnum()));
                        if(check("shstrndx","ehdr"))                        appendRecord(0,"shstrndx",XBinary::valueToHex(elf.getHdr32_shstrndx()));
                    }
                    // TODO Sections
                    // TODO Programs
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_MACHO,fileType))
        {
            XMACH mach(g_pDevice);

            if(mach.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    bool bIs64=mach.is64();

                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(mach.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap=mach.getMemoryMap();

                    if(check("Entry point(Address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(mach.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(mach.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(mach.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point")) appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point")) appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

                    if(check("magic","header"))                             appendRecord(0,"magic",XBinary::valueToHex(mach.getHeader_magic()));
                    if(check("cputype","header"))                           appendRecord(0,"cputype",XBinary::valueToHex(mach.getHeader_cputype()));
                    if(check("cpusubtype","header"))                        appendRecord(0,"cpusubtype",XBinary::valueToHex(mach.getHeader_cpusubtype()));
                    if(check("filetype","header"))                          appendRecord(0,"filetype",XBinary::valueToHex(mach.getHeader_filetype()));
                    if(check("ncmds","header"))                             appendRecord(0,"ncmds",XBinary::valueToHex(mach.getHeader_ncmds()));
                    if(check("sizeofcmds","header"))                        appendRecord(0,"sizeofcmds",XBinary::valueToHex(mach.getHeader_sizeofcmds()));
                    if(check("flags","header"))                             appendRecord(0,"flags",XBinary::valueToHex(mach.getHeader_flags()));

                    if(bIs64)
                    {
                        if(check("reserved","header"))                      appendRecord(0,"reserved",XBinary::valueToHex(mach.getHeader_reserved()));
                    }
                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_MACHOFAT,fileType))
        {
            XMACHOFat machofat(g_pDevice);

            if(machofat.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_PE,fileType))
        {
            XPE pe(g_pDevice);

            if(pe.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(pe.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap=pe.getMemoryMap();

                    {
                        XFileInfoItem *pParent=0;

                        if(check("Entry point",""))
                        {
                            pParent=appendRecord(0,tr("Entry point"),"");
                        }

                        if(check("Entry point(Address)","Entry point"))                     appendRecord(pParent,QString("%1").arg(tr("Address")),XBinary::valueToHexEx(pe.getEntryPointAddress(&memoryMap)));
                        if(check("Entry point(Offset)","Entry point"))                      appendRecord(pParent,QString("%1").arg(tr("Offset")),XBinary::valueToHexEx(pe.getEntryPointOffset(&memoryMap)));
                        if(check("Entry point(Relative address)","Entry point"))            appendRecord(pParent,QString("%1").arg(tr("Relative address")),XBinary::valueToHexEx(pe.getEntryPointRVA(&memoryMap)));
                        if(check("Entry point(Bytes)","Entry point"))                       appendRecord(pParent,QString("%1").arg(tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                        if(check("Entry point(Signature)","Entry point"))                   appendRecord(pParent,QString("%1").arg(tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                        if(check("Entry point(Signature)(Rel)","Entry point"))              appendRecord(pParent,QString("%1(Rel)").arg(tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));
                    }

                    {
                        XFileInfoItem *pParent=0;
                        XFileInfoItem *pParentOpt=0;

                        if(check("","IMAGE_NT_HEADERS"))
                        {
                            pParent=appendRecord(0,"IMAGE_NT_HEADERS","");
                        }

                        if(check("Signature","IMAGE_NT_HEADERS"))                           appendRecord(pParent,"Signature",addFlags(XBinary::MODE_16,pe.getNtHeaders_Signature(),XPE::getImageNtHeadersSignatures(),XBinary::VL_TYPE_LIST));

                        if(check("","IMAGE_FILE_HEADER"))
                        {
                            pParentOpt=appendRecord(pParent,"IMAGE_FILE_HEADER","");
                        }

                        if(check("Machine","IMAGE_FILE_HEADER"))                            appendRecord(pParentOpt,"Machine",addFlags(XBinary::MODE_16,pe.getFileHeader_Machine(),XPE::getImageFileHeaderMachines(),XBinary::VL_TYPE_LIST));
                        if(check("NumberOfSections","IMAGE_FILE_HEADER"))                   appendRecord(pParentOpt,"NumberOfSections",XBinary::valueToHex(pe.getFileHeader_NumberOfSections()));
                        if(check("TimeDateStamp","IMAGE_FILE_HEADER"))                      appendRecord(pParentOpt,"TimeDateStamp",addDateTime(XBinary::MODE_32,XBinary::DT_TYPE_POSIX,pe.getFileHeader_TimeDateStamp()));
                        if(check("PointerToSymbolTable","IMAGE_FILE_HEADER"))               appendRecord(pParentOpt,"PointerToSymbolTable",XBinary::valueToHex(pe.getFileHeader_PointerToSymbolTable()));
                        if(check("NumberOfSymbols","IMAGE_FILE_HEADER"))                    appendRecord(pParentOpt,"NumberOfSymbols",XBinary::valueToHex(pe.getFileHeader_NumberOfSymbols()));
                        if(check("SizeOfOptionalHeader","IMAGE_FILE_HEADER"))               appendRecord(pParentOpt,"SizeOfOptionalHeader",XBinary::valueToHex(pe.getFileHeader_SizeOfOptionalHeader()));
                        if(check("Characteristics","IMAGE_FILE_HEADER"))                    appendRecord(pParentOpt,"Characteristics",addFlags(XBinary::MODE_16,pe.getFileHeader_Characteristics(),XPE::getImageFileHeaderCharacteristics(),XBinary::VL_TYPE_FLAGS));

                        if(check("","IMAGE_OPTIONAL_HEADER"))
                        {
                            pParentOpt=appendRecord(pParent,"IMAGE_OPTIONAL_HEADER","");
                        }

                        if(check("Magic","IMAGE_OPTIONAL_HEADER"))                          appendRecord(pParentOpt,"Magic",addFlags(XBinary::MODE_16,pe.getOptionalHeader_Magic(),XPE::getImageOptionalHeaderMagic(),XBinary::VL_TYPE_LIST));
                        if(check("MajorLinkerVersion","IMAGE_OPTIONAL_HEADER"))             appendRecord(pParentOpt,"MajorLinkerVersion",XBinary::valueToHex(pe.getOptionalHeader_MajorLinkerVersion()));
                        if(check("MinorLinkerVersion","IMAGE_OPTIONAL_HEADER"))             appendRecord(pParentOpt,"MinorLinkerVersion",XBinary::valueToHex(pe.getOptionalHeader_MinorLinkerVersion()));
                        if(check("SizeOfCode","IMAGE_OPTIONAL_HEADER"))                     appendRecord(pParentOpt,"SizeOfCode",XBinary::valueToHex(pe.getOptionalHeader_SizeOfCode()));
                        if(check("SizeOfInitializedData","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"SizeOfInitializedData",XBinary::valueToHex(pe.getOptionalHeader_SizeOfInitializedData()));
                        if(check("SizeOfUninitializedData","IMAGE_OPTIONAL_HEADER"))        appendRecord(pParentOpt,"SizeOfUninitializedData",XBinary::valueToHex(pe.getOptionalHeader_SizeOfUninitializedData()));
                        if(check("AddressOfEntryPoint","IMAGE_OPTIONAL_HEADER"))            appendRecord(pParentOpt,"AddressOfEntryPoint",XBinary::valueToHex(pe.getOptionalHeader_AddressOfEntryPoint()));
                        if(check("BaseOfCode","IMAGE_OPTIONAL_HEADER"))                     appendRecord(pParentOpt,"BaseOfCode",XBinary::valueToHex(pe.getOptionalHeader_BaseOfCode()));

                        if(fileType==XBinary::FT_PE32)
                        {
                            if(check("BaseOfData","IMAGE_OPTIONAL_HEADER"))                 appendRecord(pParentOpt,"BaseOfData",XBinary::valueToHex(pe.getOptionalHeader_BaseOfData()));
                            if(check("ImageBase","IMAGE_OPTIONAL_HEADER"))                  appendRecord(pParentOpt,"ImageBase",XBinary::valueToHex((quint32)pe.getOptionalHeader_ImageBase()));
                        }
                        else if(fileType==XBinary::FT_PE64)
                        {
                            if(check("ImageBase","IMAGE_OPTIONAL_HEADER"))                  appendRecord(pParentOpt,"ImageBase",XBinary::valueToHex((quint64)pe.getOptionalHeader_ImageBase()));
                        }

                        if(check("SectionAlignment","IMAGE_OPTIONAL_HEADER"))               appendRecord(pParentOpt,"SectionAlignment",XBinary::valueToHex(pe.getOptionalHeader_SectionAlignment()));
                        if(check("FileAlignment","IMAGE_OPTIONAL_HEADER"))                  appendRecord(pParentOpt,"FileAlignment",XBinary::valueToHex(pe.getOptionalHeader_FileAlignment()));
                        if(check("MajorOperatingSystemVersion","IMAGE_OPTIONAL_HEADER"))    appendRecord(pParentOpt,"MajorOperatingSystemVersion",XBinary::valueToHex(pe.getOptionalHeader_MajorOperatingSystemVersion()));
                        if(check("MinorOperatingSystemVersion","IMAGE_OPTIONAL_HEADER"))    appendRecord(pParentOpt,"MinorOperatingSystemVersion",XBinary::valueToHex(pe.getOptionalHeader_MinorOperatingSystemVersion()));
                        if(check("MajorImageVersion","IMAGE_OPTIONAL_HEADER"))              appendRecord(pParentOpt,"MajorImageVersion",XBinary::valueToHex(pe.getOptionalHeader_MajorImageVersion()));
                        if(check("MinorImageVersion","IMAGE_OPTIONAL_HEADER"))              appendRecord(pParentOpt,"MinorImageVersion",XBinary::valueToHex(pe.getOptionalHeader_MinorImageVersion()));
                        if(check("MajorSubsystemVersion","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"MajorSubsystemVersion",XBinary::valueToHex(pe.getOptionalHeader_MajorSubsystemVersion()));
                        if(check("MinorSubsystemVersion","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"MinorSubsystemVersion",XBinary::valueToHex(pe.getOptionalHeader_MinorSubsystemVersion()));
                        if(check("Win32VersionValue","IMAGE_OPTIONAL_HEADER"))              appendRecord(pParentOpt,"Win32VersionValue",XBinary::valueToHex(pe.getOptionalHeader_Win32VersionValue()));
                        if(check("SizeOfImage","IMAGE_OPTIONAL_HEADER"))                    appendRecord(pParentOpt,"SizeOfImage",XBinary::valueToHex(pe.getOptionalHeader_SizeOfImage()));
                        if(check("SizeOfHeaders","IMAGE_OPTIONAL_HEADER"))                  appendRecord(pParentOpt,"SizeOfHeaders",XBinary::valueToHex(pe.getOptionalHeader_SizeOfHeaders()));
                        if(check("CheckSum","IMAGE_OPTIONAL_HEADER"))                       appendRecord(pParentOpt,"CheckSum",XBinary::valueToHex(pe.getOptionalHeader_CheckSum()));
                        if(check("Subsystem","IMAGE_OPTIONAL_HEADER"))                      appendRecord(pParentOpt,"Subsystem",addFlags(XBinary::MODE_16,pe.getOptionalHeader_Subsystem(),XPE::getImageOptionalHeaderSubsystem(),XBinary::VL_TYPE_LIST));
                        if(check("DllCharacteristics","IMAGE_OPTIONAL_HEADER"))             appendRecord(pParentOpt,"DllCharacteristics",addFlags(XBinary::MODE_16,pe.getOptionalHeader_DllCharacteristics(),XPE::getImageOptionalHeaderDllCharacteristics(),XBinary::VL_TYPE_FLAGS));

                        if(fileType==XBinary::FT_PE32)
                        {
                            if(check("SizeOfStackReserve","IMAGE_OPTIONAL_HEADER"))         appendRecord(pParentOpt,"SizeOfStackReserve",XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfStackReserve()));
                            if(check("SizeOfStackCommit","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"SizeOfStackCommit",XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfStackCommit()));
                            if(check("SizeOfHeapReserve","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"SizeOfHeapReserve",XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfHeapReserve()));
                            if(check("SizeOfHeapCommit","IMAGE_OPTIONAL_HEADER"))           appendRecord(pParentOpt,"SizeOfHeapCommit",XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfHeapCommit()));
                        }
                        else if(fileType==XBinary::FT_PE64)
                        {
                            if(check("SizeOfStackReserve","IMAGE_OPTIONAL_HEADER"))         appendRecord(pParentOpt,"SizeOfStackReserve",XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfStackReserve()));
                            if(check("SizeOfStackCommit","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"SizeOfStackCommit",XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfStackCommit()));
                            if(check("SizeOfHeapReserve","IMAGE_OPTIONAL_HEADER"))          appendRecord(pParentOpt,"SizeOfHeapReserve",XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfHeapReserve()));
                            if(check("SizeOfHeapCommit","IMAGE_OPTIONAL_HEADER"))           appendRecord(pParentOpt,"SizeOfHeapCommit",XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfHeapCommit()));
                        }

                        if(check("LoaderFlags","IMAGE_OPTIONAL_HEADER"))                    appendRecord(pParentOpt,"LoaderFlags",XBinary::valueToHex(pe.getOptionalHeader_LoaderFlags()));
                        if(check("NumberOfRvaAndSizes","IMAGE_OPTIONAL_HEADER"))            appendRecord(pParentOpt,"NumberOfRvaAndSizes",XBinary::valueToHex(pe.getOptionalHeader_NumberOfRvaAndSizes()));

                    }

                    // TODO
                    // Sizes
                    // Directories
                    // Sections
                    // Resources
                    // Import
                    // Export
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_NE,fileType))
        {
            XNE ne(g_pDevice);

            if(ne.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(ne.getFileType()));

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
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(le.getFileType()));

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
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(msdos.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap=msdos.getMemoryMap();

                    if(check("Entry point(Address)","Entry point"))             appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Address")),XBinary::valueToHexEx(msdos.getEntryPointAddress(&memoryMap)));
                    if(check("Entry point(Offset)","Entry point"))              appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Offset")),XBinary::valueToHexEx(msdos.getEntryPointOffset(&memoryMap)));
                    if(check("Entry point(Relative address)","Entry point"))    appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Relative address")),XBinary::valueToHexEx(msdos.getEntryPointRVA(&memoryMap)));
                    if(check("Entry point(Bytes)","Entry point"))               appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Bytes")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_FULL,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)","Entry point"))           appendRecord(0,QString("%1(%2)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASK,N_SIGNATURECOUNT));
                    if(check("Entry point(Signature)(Rel)","Entry point"))      appendRecord(0,QString("%1(%2)(Rel)").arg(tr("Entry point"),tr("Signature")),XCapstone::getSignature(g_pDevice,&memoryMap,memoryMap.nEntryPointAddress,XCapstone::ST_MASKREL,N_SIGNATURECOUNT));

                    if(check("e_magic","IMAGE_DOS_HEADER"))                     appendRecord(0,"e_magic",XBinary::valueToHex(msdos.get_e_magic()));
                    if(check("e_cblp","IMAGE_DOS_HEADER"))                      appendRecord(0,"e_cblp",XBinary::valueToHex(msdos.get_e_cblp()));
                    if(check("e_cp","IMAGE_DOS_HEADER"))                        appendRecord(0,"e_cp",XBinary::valueToHex(msdos.get_e_cp()));
                    if(check("e_crlc","IMAGE_DOS_HEADER"))                      appendRecord(0,"e_crlc",XBinary::valueToHex(msdos.get_e_crlc()));
                    if(check("e_cparhdr","IMAGE_DOS_HEADER"))                   appendRecord(0,"e_cparhdr",XBinary::valueToHex(msdos.get_e_cparhdr()));
                    if(check("e_minalloc","IMAGE_DOS_HEADER"))                  appendRecord(0,"e_minalloc",XBinary::valueToHex(msdos.get_e_minalloc()));
                    if(check("e_maxalloc","IMAGE_DOS_HEADER"))                  appendRecord(0,"e_maxalloc",XBinary::valueToHex(msdos.get_e_maxalloc()));
                    if(check("e_ss","IMAGE_DOS_HEADER"))                        appendRecord(0,"e_ss",XBinary::valueToHex(msdos.get_e_ss()));
                    if(check("e_sp","IMAGE_DOS_HEADER"))                        appendRecord(0,"e_sp",XBinary::valueToHex(msdos.get_e_sp()));
                    if(check("e_csum","IMAGE_DOS_HEADER"))                      appendRecord(0,"e_csum",XBinary::valueToHex(msdos.get_e_csum()));
                    if(check("e_ip","IMAGE_DOS_HEADER"))                        appendRecord(0,"e_ip",XBinary::valueToHex(msdos.get_e_ip()));
                    if(check("e_cs","IMAGE_DOS_HEADER"))                        appendRecord(0,"e_cs",XBinary::valueToHex(msdos.get_e_cs()));
                    if(check("e_lfarlc","IMAGE_DOS_HEADER"))                    appendRecord(0,"e_lfarlc",XBinary::valueToHex(msdos.get_e_lfarlc()));
                    if(check("e_ovno","IMAGE_DOS_HEADER"))                      appendRecord(0,"e_ovno",XBinary::valueToHex(msdos.get_e_ovno()));

                    // TODO
                }
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_COM,fileType))
        {
            XCOM xcom(g_pDevice);

            if(xcom.isValid())
            {
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(xcom.getFileType()));

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
                if(!(g_pPdStruct->bIsStop))
                {
                    if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(dex.getFileType()));

                    if(check("magic","Header"))             appendRecord(0,"magic",XBinary::valueToHex(dex.getHeader_magic()));
                    if(check("version","Header"))           appendRecord(0,"version",XBinary::valueToHex(dex.getHeader_version()));
                    if(check("checksum","Header"))          appendRecord(0,"checksum",XBinary::valueToHex(dex.getHeader_checksum()));
                    if(check("signature","Header"))         appendRecord(0,"signature",dex.getHeader_signature().toHex());
                    if(check("file_size","Header"))         appendRecord(0,"file_size",XBinary::valueToHex(dex.getHeader_file_size()));
                    if(check("header_size","Header"))       appendRecord(0,"header_size",XBinary::valueToHex(dex.getHeader_header_size()));
                    if(check("endian_tag","Header"))        appendRecord(0,"endian_tag",XBinary::valueToHex(dex.getHeader_endian_tag()));
                    if(check("link_size","Header"))         appendRecord(0,"link_size",XBinary::valueToHex(dex.getHeader_link_size()));
                    if(check("link_off","Header"))          appendRecord(0,"link_off",XBinary::valueToHex(dex.getHeader_link_off()));
                    if(check("map_off","Header"))           appendRecord(0,"map_off",XBinary::valueToHex(dex.getHeader_map_off()));
                    if(check("string_ids_size","Header"))   appendRecord(0,"string_ids_size",XBinary::valueToHex(dex.getHeader_string_ids_size()));
                    if(check("string_ids_off","Header"))    appendRecord(0,"string_ids_off",XBinary::valueToHex(dex.getHeader_string_ids_off()));
                    if(check("type_ids_size","Header"))     appendRecord(0,"type_ids_size",XBinary::valueToHex(dex.getHeader_type_ids_size()));
                    if(check("type_ids_off","Header"))      appendRecord(0,"type_ids_off",XBinary::valueToHex(dex.getHeader_type_ids_off()));
                    if(check("proto_ids_size","Header"))    appendRecord(0,"proto_ids_size",XBinary::valueToHex(dex.getHeader_proto_ids_size()));
                    if(check("proto_ids_off","Header"))     appendRecord(0,"proto_ids_off",XBinary::valueToHex(dex.getHeader_proto_ids_off()));
                    if(check("field_ids_size","Header"))    appendRecord(0,"field_ids_size",XBinary::valueToHex(dex.getHeader_field_ids_size()));
                    if(check("field_ids_off","Header"))     appendRecord(0,"field_ids_off",XBinary::valueToHex(dex.getHeader_field_ids_off()));
                    if(check("method_ids_size","Header"))   appendRecord(0,"method_ids_size",XBinary::valueToHex(dex.getHeader_method_ids_size()));
                    if(check("method_ids_off","Header"))    appendRecord(0,"method_ids_off",XBinary::valueToHex(dex.getHeader_method_ids_off()));
                    if(check("class_defs_size","Header"))   appendRecord(0,"class_defs_size",XBinary::valueToHex(dex.getHeader_class_defs_size()));
                    if(check("class_defs_off","Header"))    appendRecord(0,"class_defs_off",XBinary::valueToHex(dex.getHeader_class_defs_off()));
                    if(check("data_size","Header"))         appendRecord(0,"data_size",XBinary::valueToHex(dex.getHeader_data_size()));
                    if(check("data_off","Header"))          appendRecord(0,"data_off",XBinary::valueToHex(dex.getHeader_data_off()));
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
                // TODO
            }
        }
        else if(XBinary::checkFileType(XBinary::FT_MACHOFAT,fileType))
        {
            XMACHOFat machofat(g_pDevice);

            if(machofat.isValid())
            {
                // TODO
            }
        }
        else
        {
            if(check("File type","File type")) appendRecord(0,tr("File type"),XBinary::fileTypeIdToString(XBinary::getPrefFileType(g_pDevice,true)));
        }
    }

    if(!(g_pPdStruct->bIsStop))
    {
        g_pPdStruct->pdRecordOpt.bSuccess=true;
    }

    g_pPdStruct->pdRecordOpt.bFinished=true;

    emit completed(scanTimer.elapsed());
}

