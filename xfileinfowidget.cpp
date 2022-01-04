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
#include "xfileinfowidget.h"
#include "ui_xfileinfowidget.h"

XFileInfoWidget::XFileInfoWidget(QWidget *pParent) :
    XShortcutsWidget(pParent),
    ui(new Ui::XFileInfoWidget)
{
    ui->setupUi(this);

    g_pDevice=nullptr;
    g_nOffset=0;
    g_nSize=0;
}

XFileInfoWidget::~XFileInfoWidget()
{
    delete ui;
}

void XFileInfoWidget::setData(QIODevice *pDevice, XBinary::FT fileType, bool bAuto)
{
    this->g_pDevice=pDevice;

    if(this->g_nSize==-1)
    {
        this->g_nSize=(pDevice->size())-(this->g_nOffset);
    }

    ui->lineEditOffset->setValue32_64(this->g_nOffset);
    ui->lineEditSize->setValue32_64(this->g_nSize);

    XFormats::setFileTypeComboBox(fileType,g_pDevice,ui->comboBoxType);

    if(bAuto)
    {
        reload();
    }
}

void XFileInfoWidget::reload()
{
    XFileInfo::OPTIONS options={};
//    options.bShowAll=ui->checkBoxShowAll->isChecked();

    QStandardItemModel *pModel=new QStandardItemModel;

    DialogXFileInfoProcess dip(XOptions::getMainWidget(this),g_pDevice,pModel,options);

    if(dip.exec()==QDialog::Accepted)
    {
        QString sText=XFileInfo::toFormattedString(pModel);
//        QString sText=XFileInfo::toCSV(pModel);

        ui->plainTextEditFileInfo->setPlainText(sText);
    }

    delete pModel;
}

void XFileInfoWidget::registerShortcuts(bool bState)
{
    Q_UNUSED(bState)
    // TODO !!!
}

void XFileInfoWidget::on_checkBoxShowAll_toggled(bool bChecked)
{
    Q_UNUSED(bChecked)

    reload();
}

void XFileInfoWidget::on_pushButtonSave_clicked()
{
    QString sFileName=XBinary::getResultFileName(g_pDevice,QString("%1.txt").arg(tr("Info")));
    sFileName=QFileDialog::getSaveFileName(this, tr("Save file"),sFileName, QString("%1 (*.txt);;%2 (*)").arg(tr("Text files"),tr("All files")));

    if(!sFileName.isEmpty())
    {
        XOptions::savePlainTextEdit(ui->plainTextEditFileInfo,sFileName);
    }
}

void XFileInfoWidget::on_pushButtonReload_clicked()
{
    reload();
}
