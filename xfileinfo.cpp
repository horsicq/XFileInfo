/* Copyright (c) 2021-2024 hors<horsicq@gmail.com>
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
#include "xfileinfo.h"

XFileInfo::XFileInfo(QObject *pParent) : QObject(pParent)
{
    g_pDevice = nullptr;
    g_pPdStruct = nullptr;
    g_options = {};
    g_nFreeIndex = -1;
}

void XFileInfo::setData(QIODevice *pDevice, XFileInfoModel *pModel, const OPTIONS &options, XBinary::PDSTRUCT *pPdStruct)
{
    this->g_pDevice = pDevice;
    this->g_pModel = pModel;
    this->g_options = options;
    this->g_pPdStruct = pPdStruct;
}

bool XFileInfo::processFile(const QString &sFileName, XFileInfoModel *pModel, const OPTIONS &options)
{
    bool bResult = false;

    QFile file;
    file.setFileName(sFileName);

    if (file.open(QIODevice::ReadOnly)) {
        XFileInfo fileInfo;
        XBinary::PDSTRUCT pdStruct = XBinary::createPdStruct();
        fileInfo.setData(&file, pModel, options, &pdStruct);
        fileInfo.process();
        file.close();
        bResult = true;
    }

    return bResult;
}

QList<QString> XFileInfo::getMethodNames(XBinary::FT fileType)
{
    QList<QString> listResult;

    _addMethod(&listResult, "Info");
    _addMethod(&listResult, "Hash");
    _addMethod(&listResult, "Entropy");

    if (XBinary::checkFileType(XBinary::FT_ELF, fileType)) {
        _addMethod(&listResult, "Entry point");
        _addMethod(&listResult, "Elf_Ehdr");
    } else if (XBinary::checkFileType(XBinary::FT_MACHO, fileType)) {
        _addMethod(&listResult, "Entry point");
        _addMethod(&listResult, "Header");
    } else if (XBinary::checkFileType(XBinary::FT_MACHOFAT, fileType)) {
        // TODO !!!
        // Header
        // Archs
    } else if (XBinary::checkFileType(XBinary::FT_PE, fileType)) {
        _addMethod(&listResult, "Entry point");
        _addMethod(&listResult, "IMAGE_DOS_HEADER");
        _addMethod(&listResult, "IMAGE_NT_HEADERS");
        _addMethod(&listResult, "IMAGE_SECTION_HEADER");
        // TODO !!!
    } else if (XBinary::checkFileType(XBinary::FT_NE, fileType)) {
        _addMethod(&listResult, "Entry point");
        _addMethod(&listResult, "IMAGE_DOS_HEADER");
        // TODO !!!
    } else if (XBinary::checkFileType(XBinary::FT_LE, fileType)) {
        _addMethod(&listResult, "Entry point");
        _addMethod(&listResult, "IMAGE_DOS_HEADER");
        // TODO !!!
    } else if (XBinary::checkFileType(XBinary::FT_MSDOS, fileType)) {
        _addMethod(&listResult, "Entry point");
        _addMethod(&listResult, "IMAGE_DOS_HEADER");
    } else if (XBinary::checkFileType(XBinary::FT_DEX, fileType)) {
        _addMethod(&listResult, "Header");
        // TODO
    } else if (XBinary::checkFileType(XBinary::FT_COM, fileType)) {
        _addMethod(&listResult, "Entry point");
        // TODO
    }
    //    else if(XBinary::checkFileType(XBinary::FT_PDF,fileType))
    //    {
    //        _addMethod(&listResult,"Header"),"Header");
    //    }

    return listResult;
}

XFileInfoItem *XFileInfo::appendRecord(XFileInfoItem *pItemParent, const QString &sName, QVariant varData)
{
    XFileInfoItem *pResult = new XFileInfoItem(sName, varData);

    if (pItemParent) {
        pItemParent->appendChild(pResult);
    } else {
        g_pModel->appendChild(pResult);
    }

    return pResult;
}

void XFileInfo::setCurrentStatus(const QString &sStatus)
{
    XBinary::setPdStructStatus(g_pPdStruct, g_nFreeIndex, sStatus);
}

bool XFileInfo::check(const QString &sString, const QString &sExtra1, const QString &sExtra2, const QString &sExtra3, const QString &sExtra4)
{
    QString sCurrentString = sString;

    bool bResult = true;

    if (sExtra1 != "") {
        sCurrentString += "#" + sExtra1;
    }

    if (sExtra2 != "") {
        sCurrentString += "#" + sExtra2;
    }

    if (sExtra3 != "") {
        sCurrentString += "#" + sExtra3;
    }

    if (sExtra4 != "") {
        sCurrentString += "#" + sExtra4;
    }

    qint32 nNumberOfSections = g_options.sString.count("#") + 1;

    for (qint32 i = 0; i < nNumberOfSections; i++) {
        QString sOptionString = g_options.sString.section("#", i, i).toUpper();
        QString _sString = sCurrentString.section("#", i, i).toUpper();
        if ((sOptionString != _sString) && (_sString != "")) {
            bResult = false;
        }
    }

    if (bResult) {
        setCurrentStatus(sCurrentString);
    }

    return bResult;
}

QString XFileInfo::addFlags(XBinary::MODE mode, quint64 nValue, QMap<quint64, QString> mapFlags, XBinary::VL_TYPE vlType)
{
    QString sResult = XBinary::valueToHex(mode, nValue);

    if (g_options.bComment) {
        sResult += QString("(%1)").arg(XBinary::valueToFlagsString(nValue, mapFlags, vlType));
    }

    return sResult;
}

QString XFileInfo::addDateTime(XBinary::MODE mode, XBinary::DT_TYPE dtType, quint64 nValue)
{
    QString sResult = XBinary::valueToHex(mode, nValue);

    if (g_options.bComment) {
        sResult += QString("(%1)").arg(XBinary::valueToTimeString(nValue, dtType));
    }

    return sResult;
}

void XFileInfo::_addMethod(QList<QString> *pListMethods, const QString &sName)
{
    pListMethods->append(sName);
}

void XFileInfo::_entryPoint(XBinary *pBinary, XBinary::_MEMORY_MAP *pMemoryMap)
{
    QString sGroup = "Entry point";
    if (check(sGroup)) {
        XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
        {
            QString sRecord = "Address";
            if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHexEx(pBinary->getEntryPointAddress(pMemoryMap)));
        }
        {
            QString sRecord = "Offset";
            if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHexEx(pBinary->getEntryPointOffset(pMemoryMap)));
        }
        {
            QString sRecord = "Relative address";
            if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHexEx(pBinary->getEntryPointRVA(pMemoryMap)));
        }
        {
            QString sRecord = "Bytes";
            if (check(sGroup, sRecord))
                appendRecord(pItemParent, sRecord, XCapstone::getSignature(g_pDevice, pMemoryMap, pMemoryMap->nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
        }
        {
            QString sRecord = "Signature";
            if (check(sGroup, sRecord))
                appendRecord(pItemParent, sRecord, XCapstone::getSignature(g_pDevice, pMemoryMap, pMemoryMap->nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
        }
        {
            QString sRecord = QString("%1(rel)").arg("Signature");
            if (check(sGroup, sRecord))
                appendRecord(pItemParent, sRecord,
                             XCapstone::getSignature(g_pDevice, pMemoryMap, pMemoryMap->nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));
        }
    }
}

void XFileInfo::_IMAGE_DOS_HEADER(XMSDOS *pMSDOS, bool bExtra)
{
    QString sGroup = "IMAGE_DOS_HEADER";
    if (check(sGroup)) {
        XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
        {
            {
                QString sRecord = "e_magic";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_magic()));
            }
            {
                QString sRecord = "e_cblp";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_cblp()));
            }
            {
                QString sRecord = "e_cp";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_cp()));
            }
            {
                QString sRecord = "e_crlc";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_crlc()));
            }
            {
                QString sRecord = "e_cparhdr";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_cparhdr()));
            }
            {
                QString sRecord = "e_minalloc";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_minalloc()));
            }
            {
                QString sRecord = "e_maxalloc";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_maxalloc()));
            }
            {
                QString sRecord = "e_ss";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_ss()));
            }
            {
                QString sRecord = "e_sp";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_sp()));
            }
            {
                QString sRecord = "e_csum";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_csum()));
            }
            {
                QString sRecord = "e_ip";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_ip()));
            }
            {
                QString sRecord = "e_cs";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_cs()));
            }
            {
                QString sRecord = "e_lfarlc";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_lfarlc()));
            }
            {
                QString sRecord = "e_ovno";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_ovno()));
            }
            if (bExtra) {
                // {
                //     QString sRecord = "e_res";
                //     if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_res()));
                // }
                {
                    QString sRecord = "e_oemid";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_oemid()));
                }
                {
                    QString sRecord = "e_oeminfo";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_oeminfo()));
                }
                // {
                //     QString sRecord = "e_res2";
                //     if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_res2()));
                // }
                {
                    QString sRecord = "e_lfanew";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMSDOS->get_e_lfanew()));
                }
            }
        }
    }
}

void XFileInfo::_Elf_Ehdr(XELF *pELF, bool bIs64)
{
    QString sGroup = "Elf_Ehdr";
    if (check(sGroup)) {
        XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
        {
            QString sSubGroup = "e_ident";
            if (check(sGroup, sSubGroup)) {
                XFileInfoItem *pItemSub = appendRecord(pItemParent, sSubGroup, "");
                {
                    QString sRecord = "ei_mag";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pELF->getIdent_mag_LE()));
                }
                {
                    QString sRecord = "ei_class";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pELF->getIdent_class()));
                }
                {
                    QString sRecord = "ei_data";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pELF->getIdent_data()));
                }
                {
                    QString sRecord = "ei_version";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pELF->getIdent_version()));
                }
                {
                    QString sRecord = "ei_osabi";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pELF->getIdent_osabi()));
                }
                {
                    QString sRecord = "ei_abiversion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pELF->getIdent_abiversion()));
                }
            }
        }
        {
            if (!bIs64) {
                {
                    QString sRecord = "type";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_type()));
                }
                {
                    QString sRecord = "machine";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_machine()));
                }
                {
                    QString sRecord = "version";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_version()));
                }
                {
                    QString sRecord = "entry";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_entry()));
                }
                {
                    QString sRecord = "phoff";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_phoff()));
                }
                {
                    QString sRecord = "shoff";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_shoff()));
                }
                {
                    QString sRecord = "flags";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_flags()));
                }
                {
                    QString sRecord = "ehsize";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_ehsize()));
                }
                {
                    QString sRecord = "phentsize";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_phentsize()));
                }
                {
                    QString sRecord = "phnum";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_phnum()));
                }
                {
                    QString sRecord = "shentsize";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_shentsize()));
                }
                {
                    QString sRecord = "shnum";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_shnum()));
                }
                {
                    QString sRecord = "shstrndx";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr32_shstrndx()));
                }
            } else {
                {
                    QString sRecord = "type";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_type()));
                }
                {
                    QString sRecord = "machine";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_machine()));
                }
                {
                    QString sRecord = "version";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_version()));
                }
                {
                    QString sRecord = "entry";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_entry()));
                }
                {
                    QString sRecord = "phoff";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_phoff()));
                }
                {
                    QString sRecord = "shoff";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_shoff()));
                }
                {
                    QString sRecord = "flags";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_flags()));
                }
                {
                    QString sRecord = "ehsize";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_ehsize()));
                }
                {
                    QString sRecord = "phentsize";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_phentsize()));
                }
                {
                    QString sRecord = "phnum";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_phnum()));
                }
                {
                    QString sRecord = "shentsize";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_shentsize()));
                }
                {
                    QString sRecord = "shnum";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_shnum()));
                }
                {
                    QString sRecord = "shstrndx";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pELF->getHdr64_shstrndx()));
                }
            }
        }
    }
}

void XFileInfo::_mach_header(XMACH *pMACH, bool bIs64)
{
    QString sGroup = "Header";
    if (check(sGroup)) {
        XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
        {
            {
                QString sRecord = "magic";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_magic()));
            }
            {
                QString sRecord = "cputype";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_cputype()));
            }
            {
                QString sRecord = "cpusubtype";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_cpusubtype()));
            }
            {
                QString sRecord = "filetype";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_filetype()));
            }
            {
                QString sRecord = "ncmds";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_ncmds()));
            }
            {
                QString sRecord = "sizeofcmds";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_sizeofcmds()));
            }
            {
                QString sRecord = "flags";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_flags()));
            }
            if (bIs64) {
                QString sRecord = "reserved";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pMACH->getHeader_reserved()));
            }
        }
    }
}

void XFileInfo::PE_IMAGE_NT_HEADERS(XPE *pPE, bool bIs64)
{
    QString sGroup = "IMAGE_NT_HEADERS";
    if (check(sGroup)) {
        XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
        {
            QString sRecord = "Signature";
            if (check(sGroup, sRecord))
                appendRecord(pItemParent, sRecord,
                             addFlags(XBinary::MODE_16, pPE->getNtHeaders_Signature(), XPE::getImageNtHeadersSignatures(), XBinary::VL_TYPE_LIST));
        }
        {
            QString sSubGroup = "IMAGE_FILE_HEADER";
            if (check(sGroup, sSubGroup)) {
                XFileInfoItem *pItemSub = appendRecord(pItemParent, sSubGroup, "");
                {
                    QString sRecord = "Machine";
                    if (check(sGroup, sSubGroup, sRecord))
                        appendRecord(pItemSub, sRecord,
                                     addFlags(XBinary::MODE_16, pPE->getFileHeader_Machine(), XPE::getImageFileHeaderMachines(), XBinary::VL_TYPE_LIST));
                }
                {
                    QString sRecord = "NumberOfSections";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getFileHeader_NumberOfSections()));
                }
                {
                    QString sRecord = "TimeDateStamp";
                    if (check(sGroup, sSubGroup, sRecord))
                        appendRecord(pItemSub, sRecord, addDateTime(XBinary::MODE_32, XBinary::DT_TYPE_POSIX, pPE->getFileHeader_TimeDateStamp()));
                }
                {
                    QString sRecord = "PointerToSymbolTable";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getFileHeader_PointerToSymbolTable()));
                }
                {
                    QString sRecord = "NumberOfSymbols";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getFileHeader_NumberOfSymbols()));
                }
                {
                    QString sRecord = "SizeOfOptionalHeader";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getFileHeader_SizeOfOptionalHeader()));
                }
                {
                    QString sRecord = "Characteristics";
                    if (check(sGroup, sSubGroup, sRecord))
                        appendRecord(
                            pItemSub, sRecord,
                            addFlags(XBinary::MODE_16, pPE->getFileHeader_Characteristics(), XPE::getImageFileHeaderCharacteristics(), XBinary::VL_TYPE_FLAGS));
                }
            }
        }
        {
            QString sSubGroup = "IMAGE_OPTIONAL_HEADER";
            if (check(sGroup, sSubGroup)) {
                XFileInfoItem *pItemSub = appendRecord(pItemParent, sSubGroup, "");
                {
                    QString sRecord = "Magic";
                    if (check(sGroup, sSubGroup, sRecord))
                        appendRecord(pItemSub, sRecord,
                                     addFlags(XBinary::MODE_16, pPE->getOptionalHeader_Magic(), XPE::getImageOptionalHeaderMagic(), XBinary::VL_TYPE_LIST));
                }
                {
                    QString sRecord = "MajorLinkerVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MajorLinkerVersion()));
                }
                {
                    QString sRecord = "MinorLinkerVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MinorLinkerVersion()));
                }
                {
                    QString sRecord = "SizeOfCode";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_SizeOfCode()));
                }
                {
                    QString sRecord = "SizeOfInitializedData";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_SizeOfInitializedData()));
                }
                {
                    QString sRecord = "SizeOfUninitializedData";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_SizeOfUninitializedData()));
                }
                {
                    QString sRecord = "AddressOfEntryPoint";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_AddressOfEntryPoint()));
                }
                {
                    QString sRecord = "BaseOfCode";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_BaseOfCode()));
                }

                if (!bIs64) {
                    {
                        QString sRecord = "BaseOfData";
                        if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_BaseOfData()));
                    }
                    {
                        QString sRecord = "ImageBase";
                        if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint32)pPE->getOptionalHeader_ImageBase()));
                    }
                } else {
                    {
                        QString sRecord = "ImageBase";
                        if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint64)pPE->getOptionalHeader_ImageBase()));
                    }
                }

                {
                    QString sRecord = "SectionAlignment";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_SectionAlignment()));
                }
                {
                    QString sRecord = "FileAlignment";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_FileAlignment()));
                }
                {
                    QString sRecord = "MajorOperatingSystemVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MajorOperatingSystemVersion()));
                }
                {
                    QString sRecord = "MinorOperatingSystemVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MinorOperatingSystemVersion()));
                }
                {
                    QString sRecord = "MajorImageVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MajorImageVersion()));
                }
                {
                    QString sRecord = "MinorImageVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MinorImageVersion()));
                }
                {
                    QString sRecord = "MajorSubsystemVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MajorSubsystemVersion()));
                }
                {
                    QString sRecord = "MinorSubsystemVersion";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_MinorSubsystemVersion()));
                }
                {
                    QString sRecord = "Win32VersionValue";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_Win32VersionValue()));
                }
                {
                    QString sRecord = "SizeOfImage";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_SizeOfImage()));
                }
                {
                    QString sRecord = "SizeOfHeaders";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_SizeOfHeaders()));
                }
                {
                    QString sRecord = "CheckSum";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_CheckSum()));
                }
                {
                    QString sRecord = "Subsystem";
                    if (check(sGroup, sSubGroup, sRecord))
                        appendRecord(pItemSub, sRecord,
                                     addFlags(XBinary::MODE_16, pPE->getOptionalHeader_Subsystem(), XPE::getImageOptionalHeaderSubsystem(), XBinary::VL_TYPE_LIST));
                }
                {
                    QString sRecord = "DllCharacteristics";
                    if (check(sGroup, sSubGroup, sRecord))
                        appendRecord(pItemSub, sRecord,
                                     addFlags(XBinary::MODE_16, pPE->getOptionalHeader_DllCharacteristics(), XPE::getImageOptionalHeaderDllCharacteristics(),
                                              XBinary::VL_TYPE_FLAGS));
                }

                if (!bIs64) {
                    {
                        QString sRecord = "SizeOfStackReserve";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint32)pPE->getOptionalHeader_SizeOfStackReserve()));
                    }
                    {
                        QString sRecord = "SizeOfStackCommit";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint32)pPE->getOptionalHeader_SizeOfStackCommit()));
                    }
                    {
                        QString sRecord = "SizeOfHeapReserve";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint32)pPE->getOptionalHeader_SizeOfHeapReserve()));
                    }
                    {
                        QString sRecord = "SizeOfHeapCommit";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint32)pPE->getOptionalHeader_SizeOfHeapCommit()));
                    }
                } else {
                    {
                        QString sRecord = "SizeOfStackReserve";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint64)pPE->getOptionalHeader_SizeOfStackReserve()));
                    }
                    {
                        QString sRecord = "SizeOfStackCommit";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint64)pPE->getOptionalHeader_SizeOfStackCommit()));
                    }
                    {
                        QString sRecord = "SizeOfHeapReserve";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint64)pPE->getOptionalHeader_SizeOfHeapReserve()));
                    }
                    {
                        QString sRecord = "SizeOfHeapCommit";
                        if (check(sGroup, sSubGroup, sRecord))
                            appendRecord(pItemSub, sRecord, XBinary::valueToHex((quint64)pPE->getOptionalHeader_SizeOfHeapCommit()));
                    }
                }
                {
                    QString sRecord = "LoaderFlags";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_LoaderFlags()));
                }
                {
                    QString sRecord = "NumberOfRvaAndSizes";
                    if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_NumberOfRvaAndSizes()));
                }
                QString sSubGroup2 = "IMAGE_DATA_DIRECTORY";
                if (check(sGroup, sSubGroup, sSubGroup2)) {
                    XFileInfoItem *pItemSub2 = appendRecord(pItemSub, sSubGroup2, "");
                    {
                        QMap<quint64, QString> mapDD = XPE::getImageOptionalHeaderDataDirectory();

                        qint32 nCount = qMin(pPE->getOptionalHeader_NumberOfRvaAndSizes(), (quint32)16);

                        for (int i = 0; i < nCount; i++) {
                            QString sSubGroup3 = mapDD.value(i);
                            if (check(sGroup, sSubGroup, sSubGroup2, sSubGroup3)) {
                                XFileInfoItem *pItemSub3 = appendRecord(pItemSub2, sSubGroup3, "");
                                {
                                    {
                                        QString sRecord = "VirtualAddress";
                                        if (check(sGroup, sSubGroup, sSubGroup2, sSubGroup3, sRecord)) appendRecord(pItemSub3, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_DataDirectory(i).VirtualAddress));
                                    }
                                    {
                                        QString sRecord = "Size";
                                        if (check(sGroup, sSubGroup, sSubGroup2, sSubGroup3, sRecord)) appendRecord(pItemSub3, sRecord, XBinary::valueToHex(pPE->getOptionalHeader_DataDirectory(i).Size));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void XFileInfo::PE_IMAGE_SECTION_HEADER(XPE *pPE)
{
    QString sGroup = "IMAGE_SECTION_HEADER";
    if (check(sGroup)) {
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listISH = pPE->getSectionHeaders();
        qint32 nNumberOfSections = listISH.count();

        if (nNumberOfSections > 0) {
            XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");

            for (qint32 i = 0; i < nNumberOfSections; i++) {
                QString sSectionName = QString("%1").arg(i);

                QString sSubGroup = sSectionName;
                if (check(sGroup, sSubGroup)) {
                    XFileInfoItem *pItemSub = appendRecord(pItemParent, sSubGroup, "");
                    {
                        {
                            QString sRecord = "Name";
                            if (check(sGroup, sSubGroup, sRecord)) {
                                QString _sName = QString((char *)listISH.at(i).Name);
                                _sName.resize(qMin(_sName.length(), XPE_DEF::S_IMAGE_SIZEOF_SHORT_NAME));

                                appendRecord(pItemSub, sRecord, _sName);
                            }
                        }
                        {
                            QString sRecord = "VirtualSize";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).Misc.VirtualSize));
                        }
                        {
                            QString sRecord = "VirtualAddress";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).VirtualAddress));
                        }
                        {
                            QString sRecord = "SizeOfRawData";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).SizeOfRawData));
                        }
                        {
                            QString sRecord = "PointerToRawData";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).PointerToRawData));
                        }
                        {
                            QString sRecord = "PointerToRelocations";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).PointerToRelocations));
                        }
                        {
                            QString sRecord = "PointerToLinenumbers";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).PointerToLinenumbers));
                        }
                        {
                            QString sRecord = "NumberOfRelocations";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).NumberOfRelocations));
                        }
                        {
                            QString sRecord = "NumberOfLinenumbers";
                            if (check(sGroup, sSubGroup, sRecord)) appendRecord(pItemSub, sRecord, XBinary::valueToHex(listISH.at(i).NumberOfLinenumbers));
                        }
                        {
                            QString sRecord = "Characteristics";
                            if (check(sGroup, sSubGroup, sRecord))
                                appendRecord(pItemSub, sRecord,
                                             addFlags(XBinary::MODE_32, listISH.at(i).Characteristics, XPE::getImageSectionHeaderFlags(), XBinary::VL_TYPE_FLAGS));
                        }
                    }
                }
            }
        }
    }
}

void XFileInfo::DEX_HEADER(XDEX *pDEX)
{
    QString sGroup = "Header";
    if (check(sGroup)) {
        XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
        {
            {
                QString sRecord = "magic";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_magic()));
            }
            {
                QString sRecord = "version";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_version()));
            }
            {
                QString sRecord = "checksum";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_checksum()));
            }
            {
                QString sRecord = "signature";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, pDEX->getHeader_signature().toHex());
            }
            {
                QString sRecord = "file_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_file_size()));
            }
            {
                QString sRecord = "header_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_header_size()));
            }
            {
                QString sRecord = "endian_tag";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_endian_tag()));
            }
            {
                QString sRecord = "link_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_link_size()));
            }
            {
                QString sRecord = "link_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_link_off()));
            }
            {
                QString sRecord = "map_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_map_off()));
            }
            {
                QString sRecord = "string_ids_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_string_ids_size()));
            }
            {
                QString sRecord = "string_ids_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_string_ids_off()));
            }
            {
                QString sRecord = "type_ids_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_type_ids_size()));
            }
            {
                QString sRecord = "type_ids_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_type_ids_off()));
            }
            {
                QString sRecord = "proto_ids_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_proto_ids_size()));
            }
            {
                QString sRecord = "proto_ids_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_proto_ids_off()));
            }
            {
                QString sRecord = "field_ids_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_field_ids_size()));
            }
            {
                QString sRecord = "field_ids_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_field_ids_off()));
            }
            {
                QString sRecord = "method_ids_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_method_ids_size()));
            }
            {
                QString sRecord = "method_ids_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_method_ids_size()));
            }
            {
                QString sRecord = "method_ids_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_method_ids_off()));
            }
            {
                QString sRecord = "class_defs_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_class_defs_size()));
            }
            {
                QString sRecord = "class_defs_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_class_defs_off()));
            }
            {
                QString sRecord = "data_size";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_data_size()));
            }
            {
                QString sRecord = "data_off";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::valueToHex(pDEX->getHeader_data_off()));
            }
        }
    }
}

void XFileInfo::process()
{
    QElapsedTimer scanTimer;
    scanTimer.start();

    g_nFreeIndex = XBinary::getFreeIndex(g_pPdStruct);
    XBinary::setPdStructInit(g_pPdStruct, g_nFreeIndex, 0);

    XBinary::FT fileType = g_options.fileType;

    if (fileType == XBinary::FT_UNKNOWN) {
        fileType = XBinary::getPrefFileType(g_pDevice);
    }

    {
        QString sGroup = "Info";
        if (check(sGroup)) {
            XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
            {
                QString sRecord = "File name";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getDeviceFileName(g_pDevice));
            }

            XBinary::FILEFORMATINFO fileFormatInfo = XFormats::getFileFormatInfo(fileType, g_pDevice, true, -1, g_pPdStruct);
            {
                QString sRecord = "Size";
                if (check(sGroup, sRecord)) {
                    qint64 nSize = fileFormatInfo.nSize;
                    QString sSize = QString::number(nSize);

                    if (g_options.bComment) {
                        sSize += QString("(%1)").arg(XBinary::bytesCountToString(nSize));
                    }

                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, sSize);
                }
            }
            {
                QString sRecord = "File type";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::fileTypeIdToString(fileFormatInfo.fileType));
            }
            {
                QString sRecord = "String";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, fileFormatInfo.sString);
            }
            {
                QString sRecord = "Extension";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, fileFormatInfo.sExt);
            }
            {
                QString sRecord = "Version";
                if (check(sGroup, sRecord) && (fileFormatInfo.sVersion != "")) {
                    appendRecord(pItemParent, sRecord, fileFormatInfo.sVersion);
                }
            }

            if (XBinary::checkFileType(XBinary::FT_ELF, fileType) || XBinary::checkFileType(XBinary::FT_PE, fileType) ||
                XBinary::checkFileType(XBinary::FT_MACHO, fileType) || XBinary::checkFileType(XBinary::FT_MSDOS, fileType) ||
                XBinary::checkFileType(XBinary::FT_NE, fileType) || XBinary::checkFileType(XBinary::FT_LE, fileType)) {
                XBinary::OSINFO osInfo = XFormats::getOsInfo(fileType, g_pDevice);

                {
                    QString sRecord = "Operation system";
                    if (check(sGroup, sRecord)) {
                        QString sOperationSystem = XBinary::osNameIdToString(osInfo.osName);

                        if (osInfo.sOsVersion != "") {
                            sOperationSystem += QString("(%1)").arg(osInfo.sOsVersion);
                        }

                        appendRecord(pItemParent, sRecord, sOperationSystem);
                    }
                }
                {
                    QString sRecord = "Architecture";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, osInfo.sArch);
                }
                {
                    QString sRecord = "Mode";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::modeIdToString(osInfo.mode));
                }
                {
                    QString sRecord = "Type";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, osInfo.sType);
                }
                {
                    QString sRecord = "Endianness";
                    if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::endianToString(osInfo.endian));
                }
            }
        }
    }
    {
        QString sGroup = "Hash";
        if (check(sGroup)) {
            XFileInfoItem *pItemParent = appendRecord(0, sGroup, "");
            {
                QString sRecord = "MD4";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_MD4, g_pDevice, g_pPdStruct));
            }
            {
                QString sRecord = "MD5";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_MD5, g_pDevice, g_pPdStruct));
            }
            {
                QString sRecord = "SHA1";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_SHA1, g_pDevice, g_pPdStruct));
            }
            {
                QString sRecord = "SHA224";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_SHA224, g_pDevice, g_pPdStruct));
            }
            {
                QString sRecord = "SHA256";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_SHA256, g_pDevice, g_pPdStruct));
            }
            {
                QString sRecord = "SHA384";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_SHA384, g_pDevice, g_pPdStruct));
            }
            {
                QString sRecord = "SHA512";
                if (check(sGroup, sRecord)) appendRecord(pItemParent, sRecord, XBinary::getHash(XBinary::HASH_SHA512, g_pDevice, g_pPdStruct));
            }
        }
    }
    {
        QString sRecord = "Entropy";
        if (check(sRecord)) {
            double dEntropy = XBinary::getEntropy(g_pDevice, g_pPdStruct);
            QString sEntropy = QString::number(dEntropy);

            if (g_options.bComment) {
                sEntropy += QString("(%1)").arg(XBinary::isPacked(dEntropy) ? ("packed") : ("not packed"));
            }

            appendRecord(0, sRecord, sEntropy);
        }
    }

    if (!(g_pPdStruct->bIsStop)) {
        if (XBinary::checkFileType(XBinary::FT_BINARY, fileType)) {
            XBinary binary(g_pDevice);

            if (binary.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    {
                        // TODO
                    }
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_ELF, fileType)) {
            XELF elf(g_pDevice);

            if (elf.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    bool bIs64 = elf.is64();

                    //                    XBinary::_MEMORY_MAP memoryMap = elf.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = elf.getMemoryMap(XBinary::MAPMODE_SEGMENTS, g_pPdStruct);

                    _entryPoint(&elf, &memoryMap);
                    _Elf_Ehdr(&elf, bIs64);
                    // TODO
                    // TODO Sections
                    // TODO Programs
                    // TODO rels
                    // TODO libraries
                    // TODO symbols
                    // TODO dynamic
                    // TODO notes
                    // TODO version
                    // TODO verneed
                    // TODO verdef
                    // TODO gnuhash
                    // TODO hash
                    // TODO sysvhash
                    // TODO relocations
                    // TODO relocationsaddend
                    // TODO relocationsrel
                    // TODO relocationsrela
                    // TODO relocationsplt
                    // TODO relocationspltrel
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_MACHO, fileType)) {
            XMACH mach(g_pDevice);

            if (mach.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    bool bIs64 = mach.is64();

                    //                    XBinary::_MEMORY_MAP memoryMap = mach.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = mach.getMemoryMap(XBinary::MAPMODE_SEGMENTS, g_pPdStruct);

                    _entryPoint(&mach, &memoryMap);
                    _mach_header(&mach, bIs64);
                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_MACHOFAT, fileType)) {
            XMACHOFat machofat(g_pDevice);

            if (machofat.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_PE, fileType)) {
            XPE pe(g_pDevice);

            if (pe.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    //                    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap(XBinary::MAPMODE_UNKNOWN, g_pPdStruct);
                    bool bIs64 = pe.is64();

                    _entryPoint(&pe, &memoryMap);
                    _IMAGE_DOS_HEADER(&pe, true);
                    PE_IMAGE_NT_HEADERS(&pe, bIs64);
                    PE_IMAGE_SECTION_HEADER(&pe);

                    // TODO
                    // Sizes !!!
                    // Resources
                    // Import
                    // Export
                    // Relocs
                    // Exceptions
                    // Debug
                    // TLS
                    // LoadConfig
                    // BoundImport
                    // DelayImport
                    // NET
                    // Overlay
                    // Rich
                    // Sign
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_NE, fileType)) {
            XNE ne(g_pDevice);

            if (ne.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    //                    XBinary::_MEMORY_MAP memoryMap = ne.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = ne.getMemoryMap(XBinary::MAPMODE_UNKNOWN, g_pPdStruct);

                    _entryPoint(&ne, &memoryMap);
                    _IMAGE_DOS_HEADER(&ne, true);
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_LE, fileType)) {
            XLE le(g_pDevice);

            if (le.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    //                    XBinary::_MEMORY_MAP memoryMap = le.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = le.getMemoryMap(XBinary::MAPMODE_UNKNOWN, g_pPdStruct);

                    _entryPoint(&le, &memoryMap);
                    _IMAGE_DOS_HEADER(&le, true);

                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_MSDOS, fileType)) {
            XMSDOS msdos(g_pDevice);

            if (msdos.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    //                    XBinary::_MEMORY_MAP memoryMap = msdos.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = msdos.getMemoryMap(XBinary::MAPMODE_UNKNOWN, g_pPdStruct);

                    _entryPoint(&msdos, &memoryMap);
                    _IMAGE_DOS_HEADER(&msdos, false);

                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_COM, fileType)) {
            XCOM xcom(g_pDevice);

            if (xcom.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    //                    XBinary::_MEMORY_MAP memoryMap = xcom.getMemoryMap(g_options.mapMode, g_pPdStruct);
                    XBinary::_MEMORY_MAP memoryMap = xcom.getMemoryMap(XBinary::MAPMODE_UNKNOWN, g_pPdStruct);

                    _entryPoint(&xcom, &memoryMap);
                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_DEX, fileType)) {
            XDEX dex(g_pDevice);

            if (dex.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    DEX_HEADER(&dex);
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_PDF, fileType)) {
            XPDF pdf(g_pDevice);

            if (pdf.isValid()) {
                if (check("File type")) appendRecord(0, "File type", XBinary::fileTypeIdToString(pdf.getFileType()));
                //                if(check("Version","Version"))
                //                appendRecord(0,"Version"),pdf.getVersion());
                // TODO
            }
        } else if (XBinary::checkFileType(XBinary::FT_MACHOFAT, fileType)) {
            XMACHOFat machofat(g_pDevice);

            if (machofat.isValid()) {
                // TODO
            }
        } else {
            // TODO
        }
    }

    XBinary::setPdStructFinished(g_pPdStruct, g_nFreeIndex);

    emit completed(scanTimer.elapsed());
}
