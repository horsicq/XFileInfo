/* Copyright (c) 2021-2025 hors<horsicq@gmail.com>
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
#include "dialogxfileinfo.h"

#include "ui_dialogxfileinfo.h"

DialogXFileInfo::DialogXFileInfo(QWidget *pParent) : XShortcutsDialog(pParent, true), ui(new Ui::DialogXFileInfo)
{
    ui->setupUi(this);
}

DialogXFileInfo::~DialogXFileInfo()
{
    delete ui;
}

void DialogXFileInfo::setGlobal(XShortcuts *pShortcuts, XOptions *pXOptions)
{
    ui->widget->setGlobal(pShortcuts, pXOptions);
}

void DialogXFileInfo::setData(QIODevice *pDevice, XBinary::FT fileType, const QString &sString, bool bAuto)
{
    ui->widget->setData(pDevice, fileType, sString, bAuto);
}

void DialogXFileInfo::on_pushButtonClose_clicked()
{
    this->close();
}
