/* Copyright (c) 2026 hors<horsicq@gmail.com>
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
#include "xfileinfovalues.h"
#include "die_script.h"
#include "specabstract.h"
#include "xdisasmcore.h"
#include "xoptions.h"

#include <QFileInfo>
#include <QStringList>

namespace {
const qint64 N_XFIV_BYTES = 16;
const qint32 N_XFIV_SIGNATURECOUNT = 10;

bool isBinaryValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_HEADER_BYTES) || (value == XFileInfoValues::XFIV_ENTRYPOINT_BYTES) || (value == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE) ||
           (value == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE_RELATIVE) || (value == XFileInfoValues::XFIV_OVERLAY_BYTES) ||
           (value == XFileInfoValues::XFIV_OVERLAY_SIZE) || (value == XFileInfoValues::XFIV_OVERLAY_ENTROPY);
}

bool isPEValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_TIMEDATESTAMP) || (value == XFileInfoValues::XFIV_PE_MAJORLINKERVERSION) ||
           (value == XFileInfoValues::XFIV_PE_MINORLINKERVERSION) || (value == XFileInfoValues::XFIV_PE_NUMBEROFSECTIONS) ||
           (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_ENTROPY) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_NAME) ||
           (value == XFileInfoValues::XFIV_PE_SECONDSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_ENTROPY) ||
           (value == XFileInfoValues::XFIV_PE_THIRDSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_THIRDSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_THIRDSECTION_ENTROPY) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_NAME) ||
           (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_ENTROPY) ||
           (value == XFileInfoValues::XFIV_PE_LASTSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_LASTSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_LASTSECTION_ENTROPY) || (value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_LASTIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_LASTIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_IMPORT_HASH32) ||
           (value == XFileInfoValues::XFIV_PE_IMPORT_HASH64) || (value == XFileInfoValues::XFIV_PE_EXPORT) || (value == XFileInfoValues::XFIV_PE_IMPORT) ||
           (value == XFileInfoValues::XFIV_PE_RESOURCE) || (value == XFileInfoValues::XFIV_PE_EXCEPTION) || (value == XFileInfoValues::XFIV_PE_SECURITY) ||
           (value == XFileInfoValues::XFIV_PE_BASERELOC) || (value == XFileInfoValues::XFIV_PE_DEBUG) || (value == XFileInfoValues::XFIV_PE_ARCHITECTURE) ||
           (value == XFileInfoValues::XFIV_PE_GLOBALPTR) || (value == XFileInfoValues::XFIV_PE_TLS) || (value == XFileInfoValues::XFIV_PE_LOAD_CONFIG) ||
           (value == XFileInfoValues::XFIV_PE_BOUND_IMPORT) || (value == XFileInfoValues::XFIV_PE_IAT) || (value == XFileInfoValues::XFIV_PE_DELAY_IMPORT) ||
           (value == XFileInfoValues::XFIV_PE_COM_DESCRIPTOR);
}

bool isNFDValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_NFD_LINKER) || (value == XFileInfoValues::XFIV_NFD_COMPILER) || (value == XFileInfoValues::XFIV_NFD_WRAPPER);
}

bool isDIEValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_DIE_LINKER) || (value == XFileInfoValues::XFIV_DIE_COMPILER) || (value == XFileInfoValues::XFIV_DIE_WRAPPER);
}

bool isScanValue(XFileInfoValues::XFIV value)
{
    return isNFDValue(value) || isDIEValue(value);
}

bool isPEIntegerValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_TIMEDATESTAMP) || (value == XFileInfoValues::XFIV_PE_MAJORLINKERVERSION) ||
           (value == XFileInfoValues::XFIV_PE_MINORLINKERVERSION) || (value == XFileInfoValues::XFIV_PE_NUMBEROFSECTIONS) ||
           (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_THIRDSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_LASTSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NUMBEROFFUNCTIONS) ||
           (value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NUMBEROFFUNCTIONS) ||
           (value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_LASTIMPORT_NUMBEROFFUNCTIONS) ||
           (value == XFileInfoValues::XFIV_PE_IMPORT_HASH32) || (value == XFileInfoValues::XFIV_PE_IMPORT_HASH64);
}

bool isPESectionNameValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_NAME) ||
           (value == XFileInfoValues::XFIV_PE_THIRDSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_NAME) ||
           (value == XFileInfoValues::XFIV_PE_LASTSECTION_NAME);
}

bool isPESectionEntropyValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_ENTROPY) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_ENTROPY) ||
           (value == XFileInfoValues::XFIV_PE_THIRDSECTION_ENTROPY) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_ENTROPY) ||
           (value == XFileInfoValues::XFIV_PE_LASTSECTION_ENTROPY);
}

bool isPESectionSizeValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_THIRDSECTION_SIZE) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_SIZE) ||
           (value == XFileInfoValues::XFIV_PE_LASTSECTION_SIZE);
}

bool isPEImportNameValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NAME) ||
           (value == XFileInfoValues::XFIV_PE_LASTIMPORT_NAME);
}

bool isPEImportNumberOfFunctionsValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NUMBEROFFUNCTIONS) ||
           (value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NUMBEROFFUNCTIONS) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NUMBEROFFUNCTIONS) ||
           (value == XFileInfoValues::XFIV_PE_LASTIMPORT_NUMBEROFFUNCTIONS);
}

bool isPEImportHashValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_IMPORT_HASH32) || (value == XFileInfoValues::XFIV_PE_IMPORT_HASH64);
}

bool isPEDataDirectoryValue(XFileInfoValues::XFIV value)
{
    return (value == XFileInfoValues::XFIV_PE_EXPORT) || (value == XFileInfoValues::XFIV_PE_IMPORT) || (value == XFileInfoValues::XFIV_PE_RESOURCE) ||
           (value == XFileInfoValues::XFIV_PE_EXCEPTION) || (value == XFileInfoValues::XFIV_PE_SECURITY) || (value == XFileInfoValues::XFIV_PE_BASERELOC) ||
           (value == XFileInfoValues::XFIV_PE_DEBUG) || (value == XFileInfoValues::XFIV_PE_ARCHITECTURE) || (value == XFileInfoValues::XFIV_PE_GLOBALPTR) ||
           (value == XFileInfoValues::XFIV_PE_TLS) || (value == XFileInfoValues::XFIV_PE_LOAD_CONFIG) || (value == XFileInfoValues::XFIV_PE_BOUND_IMPORT) ||
           (value == XFileInfoValues::XFIV_PE_IAT) || (value == XFileInfoValues::XFIV_PE_DELAY_IMPORT) || (value == XFileInfoValues::XFIV_PE_COM_DESCRIPTOR);
}

bool isPEStringValue(XFileInfoValues::XFIV value)
{
    return isPESectionNameValue(value) || isPEImportNameValue(value);
}

bool isPEEntropyValue(XFileInfoValues::XFIV value)
{
    return isPESectionEntropyValue(value);
}

qint32 getPESectionIndex(XFileInfoValues::XFIV value, qint32 nNumberOfSections)
{
    qint32 nResult = -1;

    if ((value == XFileInfoValues::XFIV_PE_FIRSTSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_SIZE) ||
        (value == XFileInfoValues::XFIV_PE_FIRSTSECTION_ENTROPY)) {
        nResult = 0;
    } else if ((value == XFileInfoValues::XFIV_PE_SECONDSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_SECONDSECTION_SIZE) ||
               (value == XFileInfoValues::XFIV_PE_SECONDSECTION_ENTROPY)) {
        nResult = 1;
    } else if ((value == XFileInfoValues::XFIV_PE_THIRDSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_THIRDSECTION_SIZE) ||
               (value == XFileInfoValues::XFIV_PE_THIRDSECTION_ENTROPY)) {
        nResult = 2;
    } else if ((value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_SIZE) ||
               (value == XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_ENTROPY)) {
        nResult = nNumberOfSections - 2;
    } else if ((value == XFileInfoValues::XFIV_PE_LASTSECTION_NAME) || (value == XFileInfoValues::XFIV_PE_LASTSECTION_SIZE) ||
               (value == XFileInfoValues::XFIV_PE_LASTSECTION_ENTROPY)) {
        nResult = nNumberOfSections - 1;
    }

    if ((nResult < 0) || (nResult >= nNumberOfSections)) {
        nResult = -1;
    }

    return nResult;
}

qint32 getPEImportIndex(XFileInfoValues::XFIV value, qint32 nNumberOfImports)
{
    qint32 nResult = -1;

    if ((value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_FIRSTIMPORT_NUMBEROFFUNCTIONS)) {
        nResult = 0;
    } else if ((value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_SECONDIMPORT_NUMBEROFFUNCTIONS)) {
        nResult = 1;
    } else if ((value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_THIRDIMPORT_NUMBEROFFUNCTIONS)) {
        nResult = 2;
    } else if ((value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NUMBEROFFUNCTIONS)) {
        nResult = nNumberOfImports - 2;
    } else if ((value == XFileInfoValues::XFIV_PE_LASTIMPORT_NAME) || (value == XFileInfoValues::XFIV_PE_LASTIMPORT_NUMBEROFFUNCTIONS)) {
        nResult = nNumberOfImports - 1;
    }

    if ((nResult < 0) || (nResult >= nNumberOfImports)) {
        nResult = -1;
    }

    return nResult;
}

qint32 getPEDataDirectoryNumber(XFileInfoValues::XFIV value)
{
    qint32 nResult = -1;

    if (value == XFileInfoValues::XFIV_PE_EXPORT) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXPORT;
    } else if (value == XFileInfoValues::XFIV_PE_IMPORT) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT;
    } else if (value == XFileInfoValues::XFIV_PE_RESOURCE) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE;
    } else if (value == XFileInfoValues::XFIV_PE_EXCEPTION) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_EXCEPTION;
    } else if (value == XFileInfoValues::XFIV_PE_SECURITY) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY;
    } else if (value == XFileInfoValues::XFIV_PE_BASERELOC) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC;
    } else if (value == XFileInfoValues::XFIV_PE_DEBUG) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_DEBUG;
    } else if (value == XFileInfoValues::XFIV_PE_ARCHITECTURE) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE;
    } else if (value == XFileInfoValues::XFIV_PE_GLOBALPTR) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_GLOBALPTR;
    } else if (value == XFileInfoValues::XFIV_PE_TLS) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_TLS;
    } else if (value == XFileInfoValues::XFIV_PE_LOAD_CONFIG) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG;
    } else if (value == XFileInfoValues::XFIV_PE_BOUND_IMPORT) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT;
    } else if (value == XFileInfoValues::XFIV_PE_IAT) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT;
    } else if (value == XFileInfoValues::XFIV_PE_DELAY_IMPORT) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;
    } else if (value == XFileInfoValues::XFIV_PE_COM_DESCRIPTOR) {
        nResult = XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
    }

    return nResult;
}
}  // namespace

XBinary::XIDSTRING _TABLE_XFIV[] = {
    {XFileInfoValues::XFIV_NAME, QObject::tr("Name")},
    {XFileInfoValues::XFIV_SIZE, QObject::tr("Size")},
    {XFileInfoValues::XFIV_EXTENSION, QObject::tr("Extension")},
    {XFileInfoValues::XFIV_FILETYPE, QObject::tr("File type")},
    {XFileInfoValues::XFIV_ENTROPY, QObject::tr("Entropy")},
    {XFileInfoValues::XFIV_ARCH, QObject::tr("Architecture")},
    {XFileInfoValues::XFIV_HEADER_BYTES, QObject::tr("Header bytes")},
    {XFileInfoValues::XFIV_ENTRYPOINT_BYTES, QObject::tr("Entry point bytes")},
    {XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE, QObject::tr("Entry point signature")},
    {XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE_RELATIVE, QObject::tr("Entry point signature relative")},
    {XFileInfoValues::XFIV_OVERLAY_BYTES, QObject::tr("Overlay bytes")},
    {XFileInfoValues::XFIV_OVERLAY_SIZE, QObject::tr("Overlay size")},
    {XFileInfoValues::XFIV_OVERLAY_ENTROPY, QObject::tr("Overlay entropy")},
    {XFileInfoValues::XFIV_PE_TIMEDATESTAMP, QObject::tr("PE TimeDateStamp")},
    {XFileInfoValues::XFIV_PE_MAJORLINKERVERSION, QObject::tr("PE MajorLinkerVersion")},
    {XFileInfoValues::XFIV_PE_MINORLINKERVERSION, QObject::tr("PE MinorLinkerVersion")},
    {XFileInfoValues::XFIV_PE_NUMBEROFSECTIONS, QObject::tr("PE NumberOfSections")},
    {XFileInfoValues::XFIV_PE_FIRSTSECTION_NAME, QObject::tr("PE first section name")},
    {XFileInfoValues::XFIV_PE_FIRSTSECTION_SIZE, QObject::tr("PE first section size")},
    {XFileInfoValues::XFIV_PE_FIRSTSECTION_ENTROPY, QObject::tr("PE first section entropy")},
    {XFileInfoValues::XFIV_PE_SECONDSECTION_NAME, QObject::tr("PE second section name")},
    {XFileInfoValues::XFIV_PE_SECONDSECTION_SIZE, QObject::tr("PE second section size")},
    {XFileInfoValues::XFIV_PE_SECONDSECTION_ENTROPY, QObject::tr("PE second section entropy")},
    {XFileInfoValues::XFIV_PE_THIRDSECTION_NAME, QObject::tr("PE third section name")},
    {XFileInfoValues::XFIV_PE_THIRDSECTION_SIZE, QObject::tr("PE third section size")},
    {XFileInfoValues::XFIV_PE_THIRDSECTION_ENTROPY, QObject::tr("PE third section entropy")},
    {XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_NAME, QObject::tr("PE next-to-last section name")},
    {XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_SIZE, QObject::tr("PE next-to-last section size")},
    {XFileInfoValues::XFIV_PE_NEXTTOLASTSECTION_ENTROPY, QObject::tr("PE next-to-last section entropy")},
    {XFileInfoValues::XFIV_PE_LASTSECTION_NAME, QObject::tr("PE last section name")},
    {XFileInfoValues::XFIV_PE_LASTSECTION_SIZE, QObject::tr("PE last section size")},
    {XFileInfoValues::XFIV_PE_LASTSECTION_ENTROPY, QObject::tr("PE last section entropy")},
    {XFileInfoValues::XFIV_PE_FIRSTIMPORT_NAME, QObject::tr("PE first import name")},
    {XFileInfoValues::XFIV_PE_FIRSTIMPORT_NUMBEROFFUNCTIONS, QObject::tr("PE first import NumberOfFunctions")},
    {XFileInfoValues::XFIV_PE_SECONDIMPORT_NAME, QObject::tr("PE second import name")},
    {XFileInfoValues::XFIV_PE_SECONDIMPORT_NUMBEROFFUNCTIONS, QObject::tr("PE second import NumberOfFunctions")},
    {XFileInfoValues::XFIV_PE_THIRDIMPORT_NAME, QObject::tr("PE third import name")},
    {XFileInfoValues::XFIV_PE_THIRDIMPORT_NUMBEROFFUNCTIONS, QObject::tr("PE third import NumberOfFunctions")},
    {XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NAME, QObject::tr("PE next-to-last import name")},
    {XFileInfoValues::XFIV_PE_NEXTTOLASTIMPORT_NUMBEROFFUNCTIONS, QObject::tr("PE next-to-last import NumberOfFunctions")},
    {XFileInfoValues::XFIV_PE_LASTIMPORT_NAME, QObject::tr("PE last import name")},
    {XFileInfoValues::XFIV_PE_LASTIMPORT_NUMBEROFFUNCTIONS, QObject::tr("PE last import NumberOfFunctions")},
    {XFileInfoValues::XFIV_PE_IMPORT_HASH32, QObject::tr("PE import hash 32")},
    {XFileInfoValues::XFIV_PE_IMPORT_HASH64, QObject::tr("PE import hash 64")},
    {XFileInfoValues::XFIV_PE_EXPORT, QObject::tr("PE export")},
    {XFileInfoValues::XFIV_PE_IMPORT, QObject::tr("PE import")},
    {XFileInfoValues::XFIV_PE_RESOURCE, QObject::tr("PE resource")},
    {XFileInfoValues::XFIV_PE_EXCEPTION, QObject::tr("PE exception")},
    {XFileInfoValues::XFIV_PE_SECURITY, QObject::tr("PE security")},
    {XFileInfoValues::XFIV_PE_BASERELOC, QObject::tr("PE base reloc")},
    {XFileInfoValues::XFIV_PE_DEBUG, QObject::tr("PE debug")},
    {XFileInfoValues::XFIV_PE_ARCHITECTURE, QObject::tr("PE architecture")},
    {XFileInfoValues::XFIV_PE_GLOBALPTR, QObject::tr("PE global ptr")},
    {XFileInfoValues::XFIV_PE_TLS, QObject::tr("PE TLS")},
    {XFileInfoValues::XFIV_PE_LOAD_CONFIG, QObject::tr("PE load config")},
    {XFileInfoValues::XFIV_PE_BOUND_IMPORT, QObject::tr("PE bound import")},
    {XFileInfoValues::XFIV_PE_IAT, QObject::tr("PE IAT")},
    {XFileInfoValues::XFIV_PE_DELAY_IMPORT, QObject::tr("PE delay import")},
    {XFileInfoValues::XFIV_PE_COM_DESCRIPTOR, QObject::tr("PE COM descriptor")},
    {XFileInfoValues::XFIV_NFD_LINKER, QObject::tr("NFD linker")},
    {XFileInfoValues::XFIV_NFD_COMPILER, QObject::tr("NFD compiler")},
    {XFileInfoValues::XFIV_NFD_WRAPPER, QObject::tr("NFD wrapper")},
    {XFileInfoValues::XFIV_DIE_LINKER, QObject::tr("DiE linker")},
    {XFileInfoValues::XFIV_DIE_COMPILER, QObject::tr("DiE compiler")},
    {XFileInfoValues::XFIV_DIE_WRAPPER, QObject::tr("DiE wrapper")},
};

const qint32 N_XFIV = sizeof(_TABLE_XFIV) / sizeof(XBinary::XIDSTRING);

bool XFileInfoValues_Sort::operator()(const XFileInfoValues::RecordInfo &recordInfo1, const XFileInfoValues::RecordInfo &recordInfo2) const
{
    if (recordInfo1.bIsDir != recordInfo2.bIsDir) {
        return recordInfo1.bIsDir;
    }

    if ((xFIV == XFileInfoValues::XFIV_SIZE) || (xFIV == XFileInfoValues::XFIV_OVERLAY_SIZE) || isPEIntegerValue(xFIV) || isPEDataDirectoryValue(xFIV)) {
        quint64 nSize1 = recordInfo1.mapValues.value(xFIV).toULongLong();
        quint64 nSize2 = recordInfo2.mapValues.value(xFIV).toULongLong();

        if (nSize1 != nSize2) {
            return (sortOrder == Qt::DescendingOrder) ? (nSize2 < nSize1) : (nSize1 < nSize2);
        }
    } else if ((xFIV == XFileInfoValues::XFIV_EXTENSION) || (xFIV == XFileInfoValues::XFIV_FILETYPE) || (xFIV == XFileInfoValues::XFIV_ARCH) || isPEStringValue(xFIV) ||
               isScanValue(xFIV)) {
        QString sValue1 = recordInfo1.mapValues.value(xFIV).toString().toCaseFolded();
        QString sValue2 = recordInfo2.mapValues.value(xFIV).toString().toCaseFolded();

        if (sValue1 != sValue2) {
            return (sortOrder == Qt::DescendingOrder) ? (sValue2 < sValue1) : (sValue1 < sValue2);
        }
    } else if ((xFIV == XFileInfoValues::XFIV_ENTROPY) || (xFIV == XFileInfoValues::XFIV_OVERLAY_ENTROPY) || isPEEntropyValue(xFIV)) {
        double dEntropy1 = recordInfo1.mapValues.value(xFIV).toDouble();
        double dEntropy2 = recordInfo2.mapValues.value(xFIV).toDouble();

        if (dEntropy1 != dEntropy2) {
            return (sortOrder == Qt::DescendingOrder) ? (dEntropy2 < dEntropy1) : (dEntropy1 < dEntropy2);
        }
    } else if ((xFIV == XFileInfoValues::XFIV_HEADER_BYTES) || (xFIV == XFileInfoValues::XFIV_ENTRYPOINT_BYTES) || (xFIV == XFileInfoValues::XFIV_OVERLAY_BYTES) ||
               (xFIV == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE) || (xFIV == XFileInfoValues::XFIV_ENTRYPOINT_SIGNATURE_RELATIVE)) {
        QString sValue1 = recordInfo1.mapValues.value(xFIV).toString();
        QString sValue2 = recordInfo2.mapValues.value(xFIV).toString();

        if (sValue1 != sValue2) {
            return (sortOrder == Qt::DescendingOrder) ? (sValue2 < sValue1) : (sValue1 < sValue2);
        }
    }

    QString sFileName1 = recordInfo1.sFileName.toCaseFolded();
    QString sFileName2 = recordInfo2.sFileName.toCaseFolded();

    if (sFileName1 == sFileName2) {
        return false;
    }

    return (sortOrder == Qt::DescendingOrder) ? (sFileName2 < sFileName1) : (sFileName1 < sFileName2);
}

XFileInfoValues::XFileInfoValues(QObject *pParent) : XThreadObject(pParent)
{
    m_pData = nullptr;
    m_pPdStruct = nullptr;
    m_pOptions = nullptr;
}

void XFileInfoValues::setData(XFIDATA *pData, XBinary::PDSTRUCT *pPdStruct, XOptions *pOptions)
{
    m_pData = pData;
    m_pPdStruct = pPdStruct;
    m_pOptions = pOptions;
}

void XFileInfoValues::process()
{
    if (!m_pData) {
        return;
    }

    qint32 nNumberOfFiles = m_pData->listRecords.count();
    qint32 nFreeIndex = XBinary::getFreeIndex(m_pPdStruct);
    XBinary::setPdStructInit(m_pPdStruct, nFreeIndex, nNumberOfFiles);

    for (qint32 i = 0; (i < nNumberOfFiles) && XBinary::isPdStructNotCanceled(m_pPdStruct); i++) {
        QString sFileName = m_pData->listRecords.at(i).sFilePath;

        XBinary::setPdStructStatus(m_pPdStruct, nFreeIndex, sFileName);
        m_pData->listRecords[i].mapValues = getValues(sFileName, &(m_pData->listFIV), m_pPdStruct, m_pOptions);
        XBinary::setPdStructCurrent(m_pPdStruct, nFreeIndex, i + 1);
    }

    XBinary::setPdStructFinished(m_pPdStruct, nFreeIndex);
}

QString XFileInfoValues::getTitle()
{
    return tr("File info values");
}

QString XFileInfoValues::valueIdToString(XFIV value)
{
    return XBinary::XIDSTRING_idToString(static_cast<quint64>(value), _TABLE_XFIV, N_XFIV);
}

XFileInfoValues::XFIV XFileInfoValues::valueStringToId(const QString &sValue)
{
    QString _sValue = sValue.toUpper().remove(" ").remove("-");

    return static_cast<XFileInfoValues::XFIV>(XBinary::XIDSTRING_ftStringToId(_sValue, _TABLE_XFIV, N_XFIV));
}

QVariant XFileInfoValues::getDisplayRole(QVariant varValue, XFIV value)
{
    QVariant result = varValue;

    if (varValue.isValid()) {
        if ((value == XFIV_SIZE) || (value == XFIV_OVERLAY_SIZE) || isPESectionSizeValue(value)) {
            result = XBinary::bytesCountToString(varValue.toLongLong(), 1024);
        } else if (value == XFIV_PE_TIMEDATESTAMP) {
            result = XBinary::valueToHex(static_cast<quint32>(varValue.toUInt()));
        } else if (value == XFIV_PE_IMPORT_HASH32) {
            result = XBinary::valueToHex(static_cast<quint32>(varValue.toUInt()));
        } else if (value == XFIV_PE_IMPORT_HASH64) {
            result = XBinary::valueToHex(static_cast<quint64>(varValue.toULongLong()));
        } else if (isPEDataDirectoryValue(value)) {
            result = XBinary::valueToHex(static_cast<quint32>(varValue.toUInt()));
        } else if ((value == XFIV_ENTROPY) || (value == XFIV_OVERLAY_ENTROPY) || isPEEntropyValue(value)) {
            result = QString::number(varValue.toDouble(), 'f', 4);
        }
    }

    return result;
}

int XFileInfoValues::getTextAlignmentRole(XFIV value)
{
    int result = Qt::AlignLeft;

    if ((value == XFIV_SIZE) || (value == XFIV_ENTROPY) || (value == XFIV_OVERLAY_SIZE) || (value == XFIV_OVERLAY_ENTROPY) ||
        (isPEValue(value) && !isPEStringValue(value))) {
        result = static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
    }

    return result;
}

#ifdef QT_WIDGETS_LIB
QList<XComboBoxEx::CUSTOM_FLAG> XFileInfoValues::getColumnCustomFlags()
{
    QList<XComboBoxEx::CUSTOM_FLAG> listResult;

    for (qint32 i = 0; i < N_XFIV; i++) {
        XFIV value = static_cast<XFIV>(_TABLE_XFIV[i].nID);
        bool bChecked = ((value == XFIV_NAME) || (value == XFIV_SIZE) || (value == XFIV_EXTENSION));
        bool bReadonly = (value == XFIV_NAME);

        XComboBoxEx::_addCustomFlag(&listResult, value, valueIdToString(value), bChecked, bReadonly);
    }

    return listResult;
}
#endif

QHash<XFileInfoValues::XFIV, QVariant> XFileInfoValues::getValues(const QString &sFileName, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct, XOptions *pOptions)
{
    QFile file(sFileName);

    QHash<XFileInfoValues::XFIV, QVariant> result;

    if (XBinary::isPdStructNotCanceled(pPdStruct) && file.open(QIODevice::ReadOnly)) {
        result = getValues(&file, pList, pPdStruct, pOptions);
        file.close();
    } else {
        for (qint32 i = 0; i < pList->size(); i++) {
            result.insert(pList->at(i), QVariant());
        }
    }

    return result;
}

QHash<XFileInfoValues::XFIV, QVariant> XFileInfoValues::getValues(QIODevice *pDevice, QList<XFIV> *pList, XBinary::PDSTRUCT *pPdStruct, XOptions *pOptions)
{
    QHash<XFileInfoValues::XFIV, QVariant> result;
    XBinary::_MEMORY_MAP memoryMap = {};
    XBinary::FILEFORMATINFO fileFormatInfo = {};
    XBinary *pBinary = nullptr;
    XPE *pPE = nullptr;
    QList<XPE::SECTION_RECORD> listPESectionRecords;
    QList<XPE::IMPORT_HEADER> listPEImportHeaders;
    QList<XPE::IMPORT_RECORD> listPEImportRecords;
    XScanEngine::SCAN_RESULT nfdScanResult = {};
    XScanEngine::SCAN_RESULT dieScanResult = {};
    XScanEngine::SCAN_OPTIONS scanOptionsNFD = {};
    XScanEngine::SCAN_OPTIONS scanOptionsDIE = {};
    XBinary::FT fileType = XBinary::FT_UNKNOWN;
    bool bNeedFileFormatInfo = false;
    bool bNeedMemoryMap = false;
    bool bNeedPEValues = false;
    bool bNeedPESectionValues = false;
    bool bNeedPEImportValues = false;
    bool bNeedPEImportHashValues = false;
    bool bNeedNFDValues = false;
    bool bNeedDIEValues = false;

    qint32 nNumberOfValues = pList->size();

    for (qint32 i = 0; (i < nNumberOfValues) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XFIV value = pList->at(i);

        bNeedFileFormatInfo |= ((value == XFIV_FILETYPE) || (value == XFIV_ARCH));
        bNeedMemoryMap |= isBinaryValue(value);
        bNeedPEValues |= isPEValue(value);
        bNeedPESectionValues |= (isPESectionNameValue(value) || isPESectionSizeValue(value) || isPESectionEntropyValue(value));
        bNeedPEImportValues |= (isPEImportNameValue(value) || isPEImportNumberOfFunctionsValue(value));
        bNeedPEImportHashValues |= isPEImportHashValue(value);
        bNeedNFDValues |= isNFDValue(value);
        bNeedDIEValues |= isDIEValue(value);
    }

    if ((bNeedFileFormatInfo || bNeedMemoryMap || bNeedPEValues) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        fileType = XFormats::getPrefFileType(pDevice, true, pPdStruct);
        pBinary = XFormats::getClass(fileType, pDevice, false, -1);

        if (pBinary) {
            if (bNeedPEValues && XBinary::checkFileType(XBinary::FT_PE, fileType)) {
                pPE = static_cast<XPE *>(pBinary);

                if (!pPE->isValid(pPdStruct)) {
                    pPE = nullptr;
                } else {
                    if (bNeedPESectionValues) {
                        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSectionHeaders = pPE->getSectionHeaders(pPdStruct);
                        listPESectionRecords = pPE->getSectionRecords(&listSectionHeaders, pPdStruct);
                    }

                    if (bNeedPEImportValues) {
                        listPEImportHeaders = pPE->getImports(pPdStruct);
                    }

                    if (bNeedPEImportHashValues) {
                        listPEImportRecords = pPE->getImportRecords(pPdStruct);
                    }
                }
            }

            if (bNeedFileFormatInfo) {
                fileFormatInfo = pBinary->getFileFormatInfo(pPdStruct);

                if (fileFormatInfo.fileType == XBinary::FT_UNKNOWN) {
                    fileFormatInfo.fileType = fileType;
                }
            }

            if (bNeedMemoryMap) {
                memoryMap = pBinary->getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
            }
        } else {
            fileFormatInfo.fileType = fileType;
        }
    }

    if (bNeedNFDValues && XBinary::isPdStructNotCanceled(pPdStruct)) {
        qint64 nDevicePos = pDevice->isSequential() ? -1 : pDevice->pos();
        quint64 nFlags = XScanEngine::getScanFlagsFromGlobalOptions(pOptions);

        scanOptionsNFD = XScanEngine::getDefaultOptions(nFlags);
        SpecAbstract specAbstract;
        nfdScanResult = specAbstract.scanDevice(pDevice, &scanOptionsNFD, pPdStruct);

        if (nDevicePos != -1) {
            pDevice->seek(nDevicePos);
        }
    }

    if (bNeedDIEValues && XBinary::isPdStructNotCanceled(pPdStruct)) {
        qint64 nDevicePos = pDevice->isSequential() ? -1 : pDevice->pos();
        quint64 nFlags = XScanEngine::getScanFlagsFromGlobalOptions(pOptions);

        scanOptionsDIE = XScanEngine::getDefaultOptions(nFlags);

        quint64 nDatabases = XScanEngine::getDatabasesFromGlobalOptions(pOptions);
        XScanEngine::setDatabases(&scanOptionsDIE, nDatabases);

        scanOptionsDIE.bUseExtraDatabase = true;
        scanOptionsDIE.bUseCustomDatabase = true;

        if (pOptions && pOptions->isIDPresent(XOptions::ID_SCAN_ENGINE_DIE_ENABLED)) {
            scanOptionsDIE.sMainDatabasePath = pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_MAIN_PATH).toString();
            scanOptionsDIE.sExtraDatabasePath = pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_PATH).toString();
            scanOptionsDIE.sCustomDatabasePath = pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_PATH).toString();
            scanOptionsDIE.bUseExtraDatabase = pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_EXTRA_ENABLED).toBool();
            scanOptionsDIE.bUseCustomDatabase = pOptions->getValue(XOptions::ID_SCAN_DIE_DATABASE_CUSTOM_ENABLED).toBool();
        }

        DiE_Script dieScript;

        if (dieScript.loadDatabase(&scanOptionsDIE, pPdStruct)) {
            dieScanResult = dieScript.scanDevice(pDevice, &scanOptionsDIE, pPdStruct);
        }

        if (nDevicePos != -1) {
            pDevice->seek(nDevicePos);
        }
    }

    for (qint32 i = 0; (i < nNumberOfValues) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XFIV value = pList->at(i);

        QVariant varValue;

        if (value == XFIV_SIZE) {
            varValue = XBinary::getSize(pDevice);
        } else if (value == XFIV_EXTENSION) {
            varValue = XBinary::getDeviceFileSuffix(pDevice);
        } else if (value == XFIV_FILETYPE) {
            varValue = XBinary::fileTypeIdToString(fileFormatInfo.fileType);
        } else if (value == XFIV_ENTROPY) {
            varValue = XBinary::getEntropy(pDevice, pPdStruct);
        } else if (value == XFIV_ARCH) {
            varValue = fileFormatInfo.sArch;
        } else if (value == XFIV_NFD_LINKER) {
            varValue = XScanEngine::getLinker(&scanOptionsNFD, &nfdScanResult.listRecords);
        } else if (value == XFIV_NFD_COMPILER) {
            varValue = XScanEngine::getCompiler(&scanOptionsNFD, &nfdScanResult.listRecords);
        } else if (value == XFIV_NFD_WRAPPER) {
            varValue = XScanEngine::getWrapper(&scanOptionsNFD, &nfdScanResult.listRecords);
        } else if (value == XFIV_DIE_LINKER) {
            varValue = XScanEngine::getLinker(&scanOptionsDIE, &dieScanResult.listRecords);
        } else if (value == XFIV_DIE_COMPILER) {
            varValue = XScanEngine::getCompiler(&scanOptionsDIE, &dieScanResult.listRecords);
        } else if (value == XFIV_DIE_WRAPPER) {
            varValue = XScanEngine::getWrapper(&scanOptionsDIE, &dieScanResult.listRecords);
        } else if (value == XFIV_PE_TIMEDATESTAMP) {
            if (pPE) {
                varValue = pPE->getFileHeader_TimeDateStamp();
            }
        } else if (value == XFIV_PE_MAJORLINKERVERSION) {
            if (pPE) {
                varValue = static_cast<quint32>(pPE->getOptionalHeader_MajorLinkerVersion());
            }
        } else if (value == XFIV_PE_MINORLINKERVERSION) {
            if (pPE) {
                varValue = static_cast<quint32>(pPE->getOptionalHeader_MinorLinkerVersion());
            }
        } else if (value == XFIV_PE_NUMBEROFSECTIONS) {
            if (pPE) {
                varValue = static_cast<quint32>(pPE->getFileHeader_NumberOfSections());
            }
        } else if (isPESectionNameValue(value)) {
            qint32 nSectionIndex = getPESectionIndex(value, listPESectionRecords.count());

            if (nSectionIndex != -1) {
                varValue = listPESectionRecords.at(nSectionIndex).sName;
            }
        } else if (isPESectionSizeValue(value)) {
            qint32 nSectionIndex = getPESectionIndex(value, listPESectionRecords.count());

            if (nSectionIndex != -1) {
                varValue = listPESectionRecords.at(nSectionIndex).nSize;
            }
        } else if (isPESectionEntropyValue(value)) {
            qint32 nSectionIndex = getPESectionIndex(value, listPESectionRecords.count());

            if (nSectionIndex != -1) {
                const XPE::SECTION_RECORD &sectionRecord = listPESectionRecords.at(nSectionIndex);
                varValue = pPE->getBinaryStatus(XBinary::BSTATUS_ENTROPY, sectionRecord.nOffset, sectionRecord.nSize, pPdStruct);
            }
        } else if (isPEImportNameValue(value)) {
            qint32 nImportIndex = getPEImportIndex(value, listPEImportHeaders.count());

            if (nImportIndex != -1) {
                varValue = listPEImportHeaders.at(nImportIndex).sName;
            }
        } else if (isPEImportNumberOfFunctionsValue(value)) {
            qint32 nImportIndex = getPEImportIndex(value, listPEImportHeaders.count());

            if (nImportIndex != -1) {
                varValue = listPEImportHeaders.at(nImportIndex).listPositions.count();
            }
        } else if (isPEImportHashValue(value)) {
            if (pPE) {
                if (value == XFIV_PE_IMPORT_HASH32) {
                    varValue = pPE->getImportHash32(&listPEImportRecords, pPdStruct);
                } else if (value == XFIV_PE_IMPORT_HASH64) {
                    varValue = pPE->getImportHash64(&listPEImportRecords, pPdStruct);
                }
            }
        } else if (isPEDataDirectoryValue(value)) {
            qint32 nDirectoryNumber = getPEDataDirectoryNumber(value);

            if (pPE && (nDirectoryNumber != -1)) {
                XPE_DEF::IMAGE_DATA_DIRECTORY dataDirectory = pPE->getOptionalHeader_DataDirectory(static_cast<quint32>(nDirectoryNumber));
                varValue = dataDirectory.VirtualAddress;
            }
        } else if (value == XFIV_HEADER_BYTES) {
            varValue = pBinary ? pBinary->getSignature(0, 20) : QString();
        } else if (value == XFIV_ENTRYPOINT_BYTES) {
            varValue = pBinary ? pBinary->getSignature(pBinary->getEntryPointOffset(&memoryMap), 20) : QString();
        } else if (value == XFIV_OVERLAY_BYTES) {
            if (pBinary && pBinary->isOverlayPresent(&memoryMap, pPdStruct)) {
                varValue = pBinary->getSignature(pBinary->getOverlayOffset(), 20);
            }
        } else if ((value == XFIV_ENTRYPOINT_SIGNATURE) || (value == XFIV_ENTRYPOINT_SIGNATURE_RELATIVE)) {
            if (pBinary) {
                XDisasmCore disasmCore;
                disasmCore.setMode(XBinary::getDisasmMode(&memoryMap));

                XDisasmCore::ST signatureType = (value == XFIV_ENTRYPOINT_SIGNATURE_RELATIVE) ? XDisasmCore::ST_REL : XDisasmCore::ST_MASK;
                varValue = disasmCore.getSignature(pDevice, &memoryMap, memoryMap.nEntryPointAddress, signatureType, N_XFIV_SIGNATURECOUNT);
            }
        } else if (value == XFIV_OVERLAY_SIZE) {
            varValue = pBinary ? XBinary::getOverlaySize(&memoryMap, pPdStruct) : 0;
        } else if (value == XFIV_OVERLAY_ENTROPY) {
            if (pBinary && pBinary->isOverlayPresent(&memoryMap, pPdStruct)) {
                qint64 nOverlayOffset = XBinary::getOverlayOffset(&memoryMap, pPdStruct);
                qint64 nOverlaySize = XBinary::getOverlaySize(&memoryMap, pPdStruct);

                varValue = pBinary->getBinaryStatus(XBinary::BSTATUS_ENTROPY, nOverlayOffset, nOverlaySize, pPdStruct);
            }
        }

        result.insert(value, varValue);
    }

    if (pBinary) {
        delete pBinary;
    }

    return result;
}
