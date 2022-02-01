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
#include "dialogxfileinfoprocess.h"
#include "ui_dialogxfileinfoprocess.h"

DialogXFileInfoProcess::DialogXFileInfoProcess(QWidget *pParent, QIODevice *pDevice, XFileInfoModel *pModel, XFileInfo::OPTIONS options) :
    QDialog(pParent),
    ui(new Ui::DialogXFileInfoProcess)
{
    ui->setupUi(this);

    g_pFileInfo=new XFileInfo;
    g_pThread=new QThread;

    g_pFileInfo->moveToThread(g_pThread);

    connect(g_pThread,SIGNAL(started()),g_pFileInfo,SLOT(process()));
    connect(g_pFileInfo, SIGNAL(completed(qint64)), this, SLOT(onCompleted(qint64)));
    connect(g_pFileInfo, SIGNAL(errorMessage(QString)), this, SLOT(errorMessage(QString)));

    g_pFileInfo->setData(pDevice,pModel,options);
    g_pThread->start();

    g_pTimer=new QTimer(this);
    connect(g_pTimer, SIGNAL(timeout()), this, SLOT(timerSlot()));
    g_pTimer->start(N_REFRESH_DELAY);

    g_bIsStop=false;
}

DialogXFileInfoProcess::~DialogXFileInfoProcess()
{
    g_pFileInfo->stop(); // mb TODO if g_bIsStop !!!
    g_pTimer->stop();

    g_pThread->quit();
    g_pThread->wait();

    delete ui;

    delete g_pThread;
    delete g_pFileInfo;
}

void DialogXFileInfoProcess::on_pushButtonCancel_clicked()
{
    g_bIsStop=true;

    g_pFileInfo->stop();
}

void DialogXFileInfoProcess::onCompleted(qint64 nElapsed)
{
    Q_UNUSED(nElapsed)

    if(!g_bIsStop)
    {
        accept();
    }
    else
    {
        reject();
    }
}

void DialogXFileInfoProcess::errorMessage(QString sText)
{
    // TODO
}

void DialogXFileInfoProcess::timerSlot()
{
    QString sStatus=g_pFileInfo->getCurrentStatus();

    ui->labelStatus->setText(sStatus);
}
