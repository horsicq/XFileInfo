/* Copyright (c) 2021-2023 hors<horsicq@gmail.com>
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

void XFileInfo::setData(QIODevice *pDevice, XFileInfoModel *pModel, OPTIONS options, XBinary::PDSTRUCT *pPdStruct)
{
    this->g_pDevice = pDevice;
    this->g_pModel = pModel;
    this->g_options = options;
    this->g_pPdStruct = pPdStruct;
}

bool XFileInfo::processFile(const QString &sFileName, XFileInfoModel *pModel, OPTIONS options)
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

QList<XFileInfo::METHOD> XFileInfo::getMethodNames(XBinary::FT fileType)
{
    QList<METHOD> listResult;

    _addMethod(&listResult, tr("Info"), "Info");
    _addMethod(&listResult, tr("Hash"), "Hash");
    _addMethod(&listResult, tr("Entropy"), "Entropy");

    if (XBinary::checkFileType(XBinary::FT_ELF, fileType) || XBinary::checkFileType(XBinary::FT_MACHO, fileType) || XBinary::checkFileType(XBinary::FT_COM, fileType) ||
        XBinary::checkFileType(XBinary::FT_PE, fileType) || XBinary::checkFileType(XBinary::FT_NE, fileType) || XBinary::checkFileType(XBinary::FT_LE, fileType) ||
        XBinary::checkFileType(XBinary::FT_MSDOS, fileType)) {
        _addMethod(&listResult, tr("Entry point"), "Entry point");
    }

    if (XBinary::checkFileType(XBinary::FT_ELF, fileType)) {
        _addMethod(&listResult, "ehdr", "ehdr");
    } else if (XBinary::checkFileType(XBinary::FT_MACHO, fileType)) {
        _addMethod(&listResult, tr("Header"), "Header");
    } else if (XBinary::checkFileType(XBinary::FT_MACHOFAT, fileType)) {
        // TODO !!!
        // Header
        // Archs
    } else if (XBinary::checkFileType(XBinary::FT_PE, fileType)) {
        _addMethod(&listResult, "IMAGE_DOS_HEADER", "IMAGE_DOS_HEADER");
        _addMethod(&listResult, "IMAGE_NT_HEADERS", "IMAGE_NT_HEADERS");
        // TODO !!!
    } else if (XBinary::checkFileType(XBinary::FT_NE, fileType)) {
        // TODO !!!
    } else if (XBinary::checkFileType(XBinary::FT_LE, fileType)) {
        // TODO !!!
    } else if (XBinary::checkFileType(XBinary::FT_MSDOS, fileType)) {
        _addMethod(&listResult, "IMAGE_DOS_HEADER", "IMAGE_DOS_HEADER");
    } else if (XBinary::checkFileType(XBinary::FT_DEX, fileType)) {
        _addMethod(&listResult, tr("Header"), "Header");
        // TODO
    } else if (XBinary::checkFileType(XBinary::FT_COM, fileType)) {
        // TODO
    }
    //    else if(XBinary::checkFileType(XBinary::FT_PDF,fileType))
    //    {
    //        _addMethod(&listResult,tr("Header"),"Header");
    //    }

    return listResult;
}

XFileInfoItem *XFileInfo::appendRecord(XFileInfoItem *pItemParent, const QString &sName, QVariant varData)
{
    XFileInfoItem *pResult = nullptr;

    pResult = new XFileInfoItem(sName, varData);

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

bool XFileInfo::check(QString sString, QString sExtra)
{
    bool bResult = false;

    if (!(g_pPdStruct->bIsStop)) {
        if (g_options.sString == sString) {
            bResult = true;
        } else if (g_options.sString == sExtra) {
            bResult = true;
        }
    }

    if (bResult) {
        setCurrentStatus(sString);
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

void XFileInfo::_addMethod(QList<METHOD> *pListMethods, QString sTranslated, QString sName)
{
    METHOD method = {};

    method.sTranslated = sTranslated;
    method.sName = sName;

    pListMethods->append(method);
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

    if (check("Info", "All")) {
        XFileInfoItem *pItemParent = appendRecord(0, tr("Info"), "");

        appendRecord(pItemParent, tr("File name"), XBinary::getDeviceFileName(g_pDevice));

        qint64 nSize = g_pDevice->size();
        QString sSize = QString::number(nSize);

        if (g_options.bComment) {
            sSize += QString("(%1)").arg(XBinary::bytesCountToString(nSize));
        }

        appendRecord(pItemParent, tr("Size"), sSize);

        if (XBinary::checkFileType(XBinary::FT_ELF, fileType) || XBinary::checkFileType(XBinary::FT_PE, fileType) ||
            XBinary::checkFileType(XBinary::FT_MACHO, fileType) || XBinary::checkFileType(XBinary::FT_MSDOS, fileType) ||
            XBinary::checkFileType(XBinary::FT_NE, fileType) || XBinary::checkFileType(XBinary::FT_LE, fileType)) {
            XBinary::OSINFO osInfo = XFormats::getOsInfo(fileType, g_pDevice);

            QString sOperationSystem = XBinary::osNameIdToString(osInfo.osName);

            if (osInfo.sOsVersion != "") {
                sOperationSystem += QString("(%1)").arg(osInfo.sOsVersion);
            }

            appendRecord(pItemParent, tr("Operation system"), sOperationSystem);

            appendRecord(pItemParent, tr("Architecture"), osInfo.sArch);
            appendRecord(pItemParent, tr("Mode"), XBinary::modeIdToString(osInfo.mode));
            appendRecord(pItemParent, tr("Type"), osInfo.sType);
            appendRecord(pItemParent, tr("Endianness"), XBinary::endiannessToString(osInfo.bIsBigEndian));
        }
    }

    if (check("Hash", "All")) {
        XFileInfoItem *pParent = appendRecord(0, tr("Hash"), "");

        appendRecord(pParent, "MD4", XBinary::getHash(XBinary::HASH_MD4, g_pDevice, g_pPdStruct));
        appendRecord(pParent, "MD5", XBinary::getHash(XBinary::HASH_MD5, g_pDevice, g_pPdStruct));
        appendRecord(pParent, "SHA1", XBinary::getHash(XBinary::HASH_SHA1, g_pDevice, g_pPdStruct));
        appendRecord(pParent, "SHA224", XBinary::getHash(XBinary::HASH_SHA224, g_pDevice, g_pPdStruct));
        appendRecord(pParent, "SHA256", XBinary::getHash(XBinary::HASH_SHA256, g_pDevice, g_pPdStruct));
        appendRecord(pParent, "SHA384", XBinary::getHash(XBinary::HASH_SHA384, g_pDevice, g_pPdStruct));
        appendRecord(pParent, "SHA512", XBinary::getHash(XBinary::HASH_SHA512, g_pDevice, g_pPdStruct));
    }

    if (check("Entropy", "All")) {
        XFileInfoItem *pParent = appendRecord(0, tr("Entropy"), "");

        double dEntropy = XBinary::getEntropy(g_pDevice, g_pPdStruct);
        QString sEntropy = QString::number(dEntropy);

        if (g_options.bComment) {
            sEntropy += QString("(%1)").arg(XBinary::isPacked(dEntropy) ? (tr("packed")) : (tr("not packed")));
        }

        appendRecord(pParent, tr("Entropy"), sEntropy);
    }

    if (!(g_pPdStruct->bIsStop)) {
        if (XBinary::checkFileType(XBinary::FT_BINARY, fileType)) {
            XBinary binary(g_pDevice);

            if (binary.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(binary.getFileType()));
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_ELF, fileType)) {
            XELF elf(g_pDevice);

            if (elf.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    bool bIs64 = elf.is64();

                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(elf.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap = elf.getMemoryMap();

                    if (check("Entry point(Address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Address")), XBinary::valueToHexEx(elf.getEntryPointAddress(&memoryMap)));
                    if (check("Entry point(Offset)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Offset")), XBinary::valueToHexEx(elf.getEntryPointOffset(&memoryMap)));
                    if (check("Entry point(Relative address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Relative address")), XBinary::valueToHexEx(elf.getEntryPointRVA(&memoryMap)));
                    if (check("Entry point(Bytes)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)(Rel)", "Entry point"))
                        appendRecord(0, QString("%1(%2)(Rel)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));

                    if (check("ident_mag", "ident")) appendRecord(0, "ident_mag", XBinary::valueToHex(elf.getIdent_mag_LE()));
                    if (check("ident_class", "ident")) appendRecord(0, "ident_class", XBinary::valueToHex(elf.getIdent_class()));
                    if (check("ident_data", "ident")) appendRecord(0, "ident_data", XBinary::valueToHex(elf.getIdent_data()));
                    if (check("ident_version", "ident")) appendRecord(0, "ident_version", XBinary::valueToHex(elf.getIdent_version()));
                    if (check("ident_osabi", "ident")) appendRecord(0, "ident_osabi", XBinary::valueToHex(elf.getIdent_osabi()));
                    if (check("ident_abiversion", "ident")) appendRecord(0, "ident_abiversion", XBinary::valueToHex(elf.getIdent_abiversion()));

                    if (bIs64) {
                        if (check("type", "ehdr")) appendRecord(0, "type", XBinary::valueToHex(elf.getHdr64_type()));
                        if (check("machine", "ehdr")) appendRecord(0, "machine", XBinary::valueToHex(elf.getHdr64_machine()));
                        if (check("version", "ehdr")) appendRecord(0, "version", XBinary::valueToHex(elf.getHdr64_version()));
                        if (check("entry", "ehdr")) appendRecord(0, "entry", XBinary::valueToHex(elf.getHdr64_entry()));
                        if (check("phoff", "ehdr")) appendRecord(0, "phoff", XBinary::valueToHex(elf.getHdr64_phoff()));
                        if (check("shoff", "ehdr")) appendRecord(0, "shoff", XBinary::valueToHex(elf.getHdr64_shoff()));
                        if (check("flags", "ehdr")) appendRecord(0, "flags", XBinary::valueToHex(elf.getHdr64_flags()));
                        if (check("ehsize", "ehdr")) appendRecord(0, "ehsize", XBinary::valueToHex(elf.getHdr64_ehsize()));
                        if (check("phentsize", "ehdr")) appendRecord(0, "phentsize", XBinary::valueToHex(elf.getHdr64_phentsize()));
                        if (check("phnum", "ehdr")) appendRecord(0, "phnum", XBinary::valueToHex(elf.getHdr64_phnum()));
                        if (check("shentsize", "ehdr")) appendRecord(0, "shentsize", XBinary::valueToHex(elf.getHdr64_shentsize()));
                        if (check("shnum", "ehdr")) appendRecord(0, "shnum", XBinary::valueToHex(elf.getHdr64_shnum()));
                        if (check("shstrndx", "ehdr")) appendRecord(0, "shstrndx", XBinary::valueToHex(elf.getHdr64_shstrndx()));
                    } else {
                        if (check("type", "ehdr")) appendRecord(0, "type", XBinary::valueToHex(elf.getHdr32_type()));
                        if (check("machine", "ehdr")) appendRecord(0, "machine", XBinary::valueToHex(elf.getHdr32_machine()));
                        if (check("version", "ehdr")) appendRecord(0, "version", XBinary::valueToHex(elf.getHdr32_version()));
                        if (check("entry", "ehdr")) appendRecord(0, "entry", XBinary::valueToHex(elf.getHdr32_entry()));
                        if (check("phoff", "ehdr")) appendRecord(0, "phoff", XBinary::valueToHex(elf.getHdr32_phoff()));
                        if (check("shoff", "ehdr")) appendRecord(0, "shoff", XBinary::valueToHex(elf.getHdr32_shoff()));
                        if (check("flags", "ehdr")) appendRecord(0, "flags", XBinary::valueToHex(elf.getHdr32_flags()));
                        if (check("ehsize", "ehdr")) appendRecord(0, "ehsize", XBinary::valueToHex(elf.getHdr32_ehsize()));
                        if (check("phentsize", "ehdr")) appendRecord(0, "phentsize", XBinary::valueToHex(elf.getHdr32_phentsize()));
                        if (check("phnum", "ehdr")) appendRecord(0, "phnum", XBinary::valueToHex(elf.getHdr32_phnum()));
                        if (check("shentsize", "ehdr")) appendRecord(0, "shentsize", XBinary::valueToHex(elf.getHdr32_shentsize()));
                        if (check("shnum", "ehdr")) appendRecord(0, "shnum", XBinary::valueToHex(elf.getHdr32_shnum()));
                        if (check("shstrndx", "ehdr")) appendRecord(0, "shstrndx", XBinary::valueToHex(elf.getHdr32_shstrndx()));
                    }
                    // TODO Sections
                    // TODO Programs
                    // TODO rels
                    // TODO libraries
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_MACHO, fileType)) {
            XMACH mach(g_pDevice);

            if (mach.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    bool bIs64 = mach.is64();

                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(mach.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap = mach.getMemoryMap();

                    if (check("Entry point", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, tr("Entry point"), "");

                        appendRecord(pParent, QString("%1(%2)").arg(tr("Entry point"), tr("Address")), XBinary::valueToHexEx(mach.getEntryPointAddress(&memoryMap)));
                        appendRecord(pParent, QString("%1(%2)").arg(tr("Entry point"), tr("Offset")), XBinary::valueToHexEx(mach.getEntryPointOffset(&memoryMap)));
                        appendRecord(pParent, QString("%1(%2)").arg(tr("Entry point"), tr("Relative address")), XBinary::valueToHexEx(mach.getEntryPointRVA(&memoryMap)));
                        appendRecord(pParent, QString("%1(%2)").arg(tr("Entry point"), tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                        appendRecord(pParent, QString("%1(%2)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                        appendRecord(pParent, QString("%1(%2)(Rel)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));
                    }

                    if (check("Header", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, tr("Header"), "");

                        appendRecord(pParent, "magic", XBinary::valueToHex(mach.getHeader_magic()));
                        appendRecord(pParent, "cputype", XBinary::valueToHex(mach.getHeader_cputype()));
                        appendRecord(pParent, "cpusubtype", XBinary::valueToHex(mach.getHeader_cpusubtype()));
                        appendRecord(pParent, "filetype", XBinary::valueToHex(mach.getHeader_filetype()));
                        appendRecord(pParent, "ncmds", XBinary::valueToHex(mach.getHeader_ncmds()));
                        appendRecord(pParent, "sizeofcmds", XBinary::valueToHex(mach.getHeader_sizeofcmds()));
                        appendRecord(pParent, "flags", XBinary::valueToHex(mach.getHeader_flags()));

                        if (bIs64) {
                            appendRecord(pParent, "reserved", XBinary::valueToHex(mach.getHeader_reserved()));
                        }
                    }
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
                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(pe.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap();

                    if (check("Entry point", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, tr("Entry point"), "");

                        appendRecord(pParent, QString("%1").arg(tr("Address")), XBinary::valueToHexEx(pe.getEntryPointAddress(&memoryMap)));
                        appendRecord(pParent, QString("%1").arg(tr("Offset")), XBinary::valueToHexEx(pe.getEntryPointOffset(&memoryMap)));
                        appendRecord(pParent, QString("%1").arg(tr("Relative address")), XBinary::valueToHexEx(pe.getEntryPointRVA(&memoryMap)));
                        appendRecord(pParent, QString("%1").arg(tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                        appendRecord(pParent, QString("%1").arg(tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                        appendRecord(pParent, QString("%1(Rel)").arg(tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));
                    }

                    if (check("IMAGE_DOS_HEADER", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, "IMAGE_DOS_HEADER", "");

                        appendRecord(pParent, "e_magic", XBinary::valueToHex(pe.get_e_magic()));
                        appendRecord(pParent, "e_cblp", XBinary::valueToHex(pe.get_e_cblp()));
                        appendRecord(pParent, "e_cp", XBinary::valueToHex(pe.get_e_cp()));
                        appendRecord(pParent, "e_crlc", XBinary::valueToHex(pe.get_e_crlc()));
                        appendRecord(pParent, "e_cparhdr", XBinary::valueToHex(pe.get_e_cparhdr()));
                        appendRecord(pParent, "e_minalloc", XBinary::valueToHex(pe.get_e_minalloc()));
                        appendRecord(pParent, "e_maxalloc", XBinary::valueToHex(pe.get_e_maxalloc()));
                        appendRecord(pParent, "e_ss", XBinary::valueToHex(pe.get_e_ss()));
                        appendRecord(pParent, "e_sp", XBinary::valueToHex(pe.get_e_sp()));
                        appendRecord(pParent, "e_csum", XBinary::valueToHex(pe.get_e_csum()));
                        appendRecord(pParent, "e_ip", XBinary::valueToHex(pe.get_e_ip()));
                        appendRecord(pParent, "e_cs", XBinary::valueToHex(pe.get_e_cs()));
                        appendRecord(pParent, "e_lfarlc", XBinary::valueToHex(pe.get_e_lfarlc()));
                        appendRecord(pParent, "e_ovno", XBinary::valueToHex(pe.get_e_ovno()));
                    }

                    if (check("IMAGE_NT_HEADERS", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, "IMAGE_NT_HEADERS", "");

                        appendRecord(pParent, "Signature",
                                     addFlags(XBinary::MODE_16, pe.getNtHeaders_Signature(), XPE::getImageNtHeadersSignatures(), XBinary::VL_TYPE_LIST));

                        XFileInfoItem *pParentFH = appendRecord(pParent, "IMAGE_FILE_HEADER", "");

                        appendRecord(pParentFH, "Machine",
                                     addFlags(XBinary::MODE_16, pe.getFileHeader_Machine(), XPE::getImageFileHeaderMachines(), XBinary::VL_TYPE_LIST));
                        appendRecord(pParentFH, "NumberOfSections", XBinary::valueToHex(pe.getFileHeader_NumberOfSections()));
                        appendRecord(pParentFH, "TimeDateStamp", addDateTime(XBinary::MODE_32, XBinary::DT_TYPE_POSIX, pe.getFileHeader_TimeDateStamp()));
                        appendRecord(pParentFH, "PointerToSymbolTable", XBinary::valueToHex(pe.getFileHeader_PointerToSymbolTable()));
                        appendRecord(pParentFH, "NumberOfSymbols", XBinary::valueToHex(pe.getFileHeader_NumberOfSymbols()));
                        appendRecord(pParentFH, "SizeOfOptionalHeader", XBinary::valueToHex(pe.getFileHeader_SizeOfOptionalHeader()));
                        appendRecord(pParentFH, "Characteristics",
                                     addFlags(XBinary::MODE_16, pe.getFileHeader_Characteristics(), XPE::getImageFileHeaderCharacteristics(), XBinary::VL_TYPE_FLAGS));

                        XFileInfoItem *pParentOH = appendRecord(pParent, "IMAGE_OPTIONAL_HEADER", "");

                        appendRecord(pParentOH, "Magic",
                                     addFlags(XBinary::MODE_16, pe.getOptionalHeader_Magic(), XPE::getImageOptionalHeaderMagic(), XBinary::VL_TYPE_LIST));
                        appendRecord(pParentOH, "MajorLinkerVersion", XBinary::valueToHex(pe.getOptionalHeader_MajorLinkerVersion()));
                        appendRecord(pParentOH, "MinorLinkerVersion", XBinary::valueToHex(pe.getOptionalHeader_MinorLinkerVersion()));
                        appendRecord(pParentOH, "SizeOfCode", XBinary::valueToHex(pe.getOptionalHeader_SizeOfCode()));
                        appendRecord(pParentOH, "SizeOfInitializedData", XBinary::valueToHex(pe.getOptionalHeader_SizeOfInitializedData()));
                        appendRecord(pParentOH, "SizeOfUninitializedData", XBinary::valueToHex(pe.getOptionalHeader_SizeOfUninitializedData()));
                        appendRecord(pParentOH, "AddressOfEntryPoint", XBinary::valueToHex(pe.getOptionalHeader_AddressOfEntryPoint()));
                        appendRecord(pParentOH, "BaseOfCode", XBinary::valueToHex(pe.getOptionalHeader_BaseOfCode()));

                        if (fileType == XBinary::FT_PE32) {
                            appendRecord(pParentOH, "BaseOfData", XBinary::valueToHex(pe.getOptionalHeader_BaseOfData()));
                            appendRecord(pParentOH, "ImageBase", XBinary::valueToHex((quint32)pe.getOptionalHeader_ImageBase()));
                        } else if (fileType == XBinary::FT_PE64) {
                            appendRecord(pParentOH, "ImageBase", XBinary::valueToHex((quint64)pe.getOptionalHeader_ImageBase()));
                        }

                        appendRecord(pParentOH, "SectionAlignment", XBinary::valueToHex(pe.getOptionalHeader_SectionAlignment()));
                        appendRecord(pParentOH, "FileAlignment", XBinary::valueToHex(pe.getOptionalHeader_FileAlignment()));
                        appendRecord(pParentOH, "MajorOperatingSystemVersion", XBinary::valueToHex(pe.getOptionalHeader_MajorOperatingSystemVersion()));
                        appendRecord(pParentOH, "MinorOperatingSystemVersion", XBinary::valueToHex(pe.getOptionalHeader_MinorOperatingSystemVersion()));
                        appendRecord(pParentOH, "MajorImageVersion", XBinary::valueToHex(pe.getOptionalHeader_MajorImageVersion()));
                        appendRecord(pParentOH, "MinorImageVersion", XBinary::valueToHex(pe.getOptionalHeader_MinorImageVersion()));
                        appendRecord(pParentOH, "MajorSubsystemVersion", XBinary::valueToHex(pe.getOptionalHeader_MajorSubsystemVersion()));
                        appendRecord(pParentOH, "MinorSubsystemVersion", XBinary::valueToHex(pe.getOptionalHeader_MinorSubsystemVersion()));
                        appendRecord(pParentOH, "Win32VersionValue", XBinary::valueToHex(pe.getOptionalHeader_Win32VersionValue()));
                        appendRecord(pParentOH, "SizeOfImage", XBinary::valueToHex(pe.getOptionalHeader_SizeOfImage()));
                        appendRecord(pParentOH, "SizeOfHeaders", XBinary::valueToHex(pe.getOptionalHeader_SizeOfHeaders()));
                        appendRecord(pParentOH, "CheckSum", XBinary::valueToHex(pe.getOptionalHeader_CheckSum()));
                        appendRecord(pParentOH, "Subsystem",
                                     addFlags(XBinary::MODE_16, pe.getOptionalHeader_Subsystem(), XPE::getImageOptionalHeaderSubsystem(), XBinary::VL_TYPE_LIST));
                        appendRecord(pParentOH, "DllCharacteristics",
                                     addFlags(XBinary::MODE_16, pe.getOptionalHeader_DllCharacteristics(), XPE::getImageOptionalHeaderDllCharacteristics(),
                                              XBinary::VL_TYPE_FLAGS));

                        if (fileType == XBinary::FT_PE32) {
                            appendRecord(pParentOH, "SizeOfStackReserve", XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfStackReserve()));
                            appendRecord(pParentOH, "SizeOfStackCommit", XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfStackCommit()));
                            appendRecord(pParentOH, "SizeOfHeapReserve", XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfHeapReserve()));
                            appendRecord(pParentOH, "SizeOfHeapCommit", XBinary::valueToHex((quint32)pe.getOptionalHeader_SizeOfHeapCommit()));
                        } else if (fileType == XBinary::FT_PE64) {
                            appendRecord(pParentOH, "SizeOfStackReserve", XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfStackReserve()));
                            appendRecord(pParentOH, "SizeOfStackCommit", XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfStackCommit()));
                            appendRecord(pParentOH, "SizeOfHeapReserve", XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfHeapReserve()));
                            appendRecord(pParentOH, "SizeOfHeapCommit", XBinary::valueToHex((quint64)pe.getOptionalHeader_SizeOfHeapCommit()));
                        }

                        appendRecord(pParentOH, "LoaderFlags", XBinary::valueToHex(pe.getOptionalHeader_LoaderFlags()));
                        appendRecord(pParentOH, "NumberOfRvaAndSizes", XBinary::valueToHex(pe.getOptionalHeader_NumberOfRvaAndSizes()));

                        XFileInfoItem *pParentDD = appendRecord(pParentOH, "DataDirectory", "");

                        quint32 nNumberOfRvaAndSizes = pe.getOptionalHeader_NumberOfRvaAndSizes();

                        for (quint32 i = 0; i < nNumberOfRvaAndSizes; i++) {
                            XFileInfoItem *pParentDirectory = appendRecord(pParentDD, QString::number(i), "");

                            XPE_DEF::IMAGE_DATA_DIRECTORY idd = pe.getOptionalHeader_DataDirectory(i);

                            appendRecord(pParentDirectory, "VirtualAddress", XBinary::valueToHex(idd.VirtualAddress));
                            appendRecord(pParentDirectory, "Size", XBinary::valueToHex(idd.Size));
                        }
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
        } else if (XBinary::checkFileType(XBinary::FT_NE, fileType)) {
            XNE ne(g_pDevice);

            if (ne.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(ne.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap = ne.getMemoryMap();

                    if (check("Entry point(Address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Address")), XBinary::valueToHexEx(ne.getEntryPointAddress(&memoryMap)));
                    if (check("Entry point(Offset)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Offset")), XBinary::valueToHexEx(ne.getEntryPointOffset(&memoryMap)));
                    if (check("Entry point(Relative address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Relative address")), XBinary::valueToHexEx(ne.getEntryPointRVA(&memoryMap)));
                    if (check("Entry point(Bytes)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)(Rel)", "Entry point"))
                        appendRecord(0, QString("%1(%2)(Rel)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));

                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_LE, fileType)) {
            XLE le(g_pDevice);

            if (le.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(le.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap = le.getMemoryMap();

                    if (check("Entry point(Address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Address")), XBinary::valueToHexEx(le.getEntryPointAddress(&memoryMap)));
                    if (check("Entry point(Offset)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Offset")), XBinary::valueToHexEx(le.getEntryPointOffset(&memoryMap)));
                    if (check("Entry point(Relative address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Relative address")), XBinary::valueToHexEx(le.getEntryPointRVA(&memoryMap)));
                    if (check("Entry point(Bytes)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)(Rel)", "Entry point"))
                        appendRecord(0, QString("%1(%2)(Rel)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));

                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_MSDOS, fileType)) {
            XMSDOS msdos(g_pDevice);

            if (msdos.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    XBinary::_MEMORY_MAP memoryMap = msdos.getMemoryMap();

                    if (check("Entry point", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, tr("Entry point"), "");

                        appendRecord(pParent, QString("%1").arg(tr("Address")), XBinary::valueToHexEx(msdos.getEntryPointAddress(&memoryMap)));
                        appendRecord(pParent, QString("%1").arg(tr("Offset")), XBinary::valueToHexEx(msdos.getEntryPointOffset(&memoryMap)));
                        appendRecord(pParent, QString("%1").arg(tr("Relative address")), XBinary::valueToHexEx(msdos.getEntryPointRVA(&memoryMap)));
                        appendRecord(pParent, QString("%1").arg(tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                        appendRecord(pParent, QString("%1").arg(tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                        appendRecord(pParent, QString("%1(Rel)").arg(tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));
                    }

                    if (check("IMAGE_DOS_HEADER", "All")) {
                        XFileInfoItem *pParent = appendRecord(0, "IMAGE_DOS_HEADER", "");

                        appendRecord(pParent, "e_magic", XBinary::valueToHex(msdos.get_e_magic()));
                        appendRecord(pParent, "e_cblp", XBinary::valueToHex(msdos.get_e_cblp()));
                        appendRecord(pParent, "e_cp", XBinary::valueToHex(msdos.get_e_cp()));
                        appendRecord(pParent, "e_crlc", XBinary::valueToHex(msdos.get_e_crlc()));
                        appendRecord(pParent, "e_cparhdr", XBinary::valueToHex(msdos.get_e_cparhdr()));
                        appendRecord(pParent, "e_minalloc", XBinary::valueToHex(msdos.get_e_minalloc()));
                        appendRecord(pParent, "e_maxalloc", XBinary::valueToHex(msdos.get_e_maxalloc()));
                        appendRecord(pParent, "e_ss", XBinary::valueToHex(msdos.get_e_ss()));
                        appendRecord(pParent, "e_sp", XBinary::valueToHex(msdos.get_e_sp()));
                        appendRecord(pParent, "e_csum", XBinary::valueToHex(msdos.get_e_csum()));
                        appendRecord(pParent, "e_ip", XBinary::valueToHex(msdos.get_e_ip()));
                        appendRecord(pParent, "e_cs", XBinary::valueToHex(msdos.get_e_cs()));
                        appendRecord(pParent, "e_lfarlc", XBinary::valueToHex(msdos.get_e_lfarlc()));
                        appendRecord(pParent, "e_ovno", XBinary::valueToHex(msdos.get_e_ovno()));
                    }

                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_COM, fileType)) {
            XCOM xcom(g_pDevice);

            if (xcom.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(xcom.getFileType()));

                    XBinary::_MEMORY_MAP memoryMap = xcom.getMemoryMap();

                    if (check("Entry point(Address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Address")), XBinary::valueToHexEx(xcom.getEntryPointAddress(&memoryMap)));
                    if (check("Entry point(Offset)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Offset")), XBinary::valueToHexEx(xcom.getEntryPointOffset(&memoryMap)));
                    if (check("Entry point(Relative address)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Relative address")), XBinary::valueToHexEx(xcom.getEntryPointRVA(&memoryMap)));
                    if (check("Entry point(Bytes)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Bytes")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_FULL, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)", "Entry point"))
                        appendRecord(0, QString("%1(%2)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASK, N_SIGNATURECOUNT));
                    if (check("Entry point(Signature)(Rel)", "Entry point"))
                        appendRecord(0, QString("%1(%2)(Rel)").arg(tr("Entry point"), tr("Signature")),
                                     XCapstone::getSignature(g_pDevice, &memoryMap, memoryMap.nEntryPointAddress, XCapstone::ST_MASKREL, N_SIGNATURECOUNT));

                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_DEX, fileType)) {
            XDEX dex(g_pDevice);

            if (dex.isValid()) {
                if (!(g_pPdStruct->bIsStop)) {
                    if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(dex.getFileType()));

                    if (check("magic", "Header")) appendRecord(0, "magic", XBinary::valueToHex(dex.getHeader_magic()));
                    if (check("version", "Header")) appendRecord(0, "version", XBinary::valueToHex(dex.getHeader_version()));
                    if (check("checksum", "Header")) appendRecord(0, "checksum", XBinary::valueToHex(dex.getHeader_checksum()));
                    if (check("signature", "Header")) appendRecord(0, "signature", dex.getHeader_signature().toHex());
                    if (check("file_size", "Header")) appendRecord(0, "file_size", XBinary::valueToHex(dex.getHeader_file_size()));
                    if (check("header_size", "Header")) appendRecord(0, "header_size", XBinary::valueToHex(dex.getHeader_header_size()));
                    if (check("endian_tag", "Header")) appendRecord(0, "endian_tag", XBinary::valueToHex(dex.getHeader_endian_tag()));
                    if (check("link_size", "Header")) appendRecord(0, "link_size", XBinary::valueToHex(dex.getHeader_link_size()));
                    if (check("link_off", "Header")) appendRecord(0, "link_off", XBinary::valueToHex(dex.getHeader_link_off()));
                    if (check("map_off", "Header")) appendRecord(0, "map_off", XBinary::valueToHex(dex.getHeader_map_off()));
                    if (check("string_ids_size", "Header")) appendRecord(0, "string_ids_size", XBinary::valueToHex(dex.getHeader_string_ids_size()));
                    if (check("string_ids_off", "Header")) appendRecord(0, "string_ids_off", XBinary::valueToHex(dex.getHeader_string_ids_off()));
                    if (check("type_ids_size", "Header")) appendRecord(0, "type_ids_size", XBinary::valueToHex(dex.getHeader_type_ids_size()));
                    if (check("type_ids_off", "Header")) appendRecord(0, "type_ids_off", XBinary::valueToHex(dex.getHeader_type_ids_off()));
                    if (check("proto_ids_size", "Header")) appendRecord(0, "proto_ids_size", XBinary::valueToHex(dex.getHeader_proto_ids_size()));
                    if (check("proto_ids_off", "Header")) appendRecord(0, "proto_ids_off", XBinary::valueToHex(dex.getHeader_proto_ids_off()));
                    if (check("field_ids_size", "Header")) appendRecord(0, "field_ids_size", XBinary::valueToHex(dex.getHeader_field_ids_size()));
                    if (check("field_ids_off", "Header")) appendRecord(0, "field_ids_off", XBinary::valueToHex(dex.getHeader_field_ids_off()));
                    if (check("method_ids_size", "Header")) appendRecord(0, "method_ids_size", XBinary::valueToHex(dex.getHeader_method_ids_size()));
                    if (check("method_ids_off", "Header")) appendRecord(0, "method_ids_off", XBinary::valueToHex(dex.getHeader_method_ids_off()));
                    if (check("class_defs_size", "Header")) appendRecord(0, "class_defs_size", XBinary::valueToHex(dex.getHeader_class_defs_size()));
                    if (check("class_defs_off", "Header")) appendRecord(0, "class_defs_off", XBinary::valueToHex(dex.getHeader_class_defs_off()));
                    if (check("data_size", "Header")) appendRecord(0, "data_size", XBinary::valueToHex(dex.getHeader_data_size()));
                    if (check("data_off", "Header")) appendRecord(0, "data_off", XBinary::valueToHex(dex.getHeader_data_off()));
                    // TODO
                }
            }
        } else if (XBinary::checkFileType(XBinary::FT_PDF, fileType)) {
            XPDF pdf(g_pDevice);

            if (pdf.isValid()) {
                if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(pdf.getFileType()));
                //                if(check("Version","Version"))
                //                appendRecord(0,tr("Version"),pdf.getVersion());
                // TODO
            }
        } else if (XBinary::checkFileType(XBinary::FT_MACHOFAT, fileType)) {
            XMACHOFat machofat(g_pDevice);

            if (machofat.isValid()) {
                // TODO
            }
        } else {
            if (check("File type", "File type")) appendRecord(0, tr("File type"), XBinary::fileTypeIdToString(XBinary::getPrefFileType(g_pDevice, true)));
        }
    }

    XBinary::setPdStructFinished(g_pPdStruct, g_nFreeIndex);

    emit completed(scanTimer.elapsed());
}
