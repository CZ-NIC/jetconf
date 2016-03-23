#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QSplitter>
#include <stdio.h>
#include <stdlib.h>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->comboBox->addItem(tr("GET"));
    ui->comboBox->addItem(tr("PUT"));
    ui->comboBox->addItem(tr("POST"));
    ui->comboBox->addItem(tr("DELETE"));
    ui->certLineEdit->setText(tr("/home/pspirek/sslclient/pavel_curl.pem"));
    ui->urlPlainTextEdit->setPlainText("https://127.0.0.1:8443/restconf/data/dns-server:dns-server/zones/zone=example.com");
    ui->splitter->setStretchFactor(0,0);
    ui->splitter->setStretchFactor(1,1);
    hist_filename = tr("history.txt");
    QFile hist_file(hist_filename);
    if(hist_file.open(QIODevice::ReadOnly)) {
        QByteArray l;
        bool eof = false;
        do {
            l = hist_file.readLine();
            if(l.isEmpty()) {
                eof = true;
            }
            else {
                ui->urlListWidget->addItem(QString(l.left(l.length() - 1)));
            }
        } while(!eof);
    }

    QFile post_file(tr("post.txt"));
    if(post_file.open(QIODevice::ReadOnly)) {
        QByteArray l;
        l = post_file.readAll();
        if(!l.isEmpty()) {
            ui->postDataPlainTextEdit->setPlainText(QString(l));
        }
    }

    updateGui();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::loadTextFile()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open client certificate"), "/home/pspirek/sslclient", tr("Cert files (*.pem)"));
    this->ui->certLineEdit->setText(fileName);
}

void MainWindow::on_pushButton_clicked()
{
    FILE *fp;
    int bytes_read;
    char *buf;

    fp = popen(cmd.toStdString().c_str(), "r");

    buf = (char*)malloc(16384);
    bytes_read = fread(buf, 1, 16383, fp);
    buf[bytes_read] = '\0';

    QString str = QString(buf);
    ui->outputPlainTextEdit->setPlainText(str);

    free(buf);
    pclose(fp);

    QString url = ui->urlPlainTextEdit->toPlainText();
    if(ui->urlListWidget->findItems(url, Qt::MatchExactly).isEmpty()) {
        ui->urlListWidget->addItem(url);
        QFile hist_file(hist_filename);
        if(hist_file.open(QIODevice::Append)) {
            hist_file.write(url.toUtf8());
            hist_file.write("\n");
        }
    }
}

void MainWindow::on_pushButton_2_clicked()
{
    this->loadTextFile();
}

void MainWindow::updateGui()
{
    cmd = "curl ";
    if(ui->checkBox->isChecked()) {
        cmd += "-v ";
    }
    cmd += "--http2 -k --cert-type PEM -E ";
    cmd += ui->certLineEdit->text() + " ";
    cmd += "-X " + ui->comboBox->currentText() + " ";
    if(ui->postDataPlainTextEdit->toPlainText().length() > 0) {
        cmd += "-d '" + ui->postDataPlainTextEdit->toPlainText() + "' ";
    }
    cmd += ui->urlPlainTextEdit->toPlainText();
    if(ui->checkBox->isChecked()) {
        cmd += " 2>&1";
    }
    else {
        cmd += " 2>/dev/null";
    }

    ui->cmdPlainTextEdit->setPlainText(cmd);
}

void MainWindow::on_postDataPlainTextEdit_textChanged()
{
    updateGui();
}

void MainWindow::on_comboBox_currentIndexChanged(const QString &arg1)
{
    Q_UNUSED(arg1)
    updateGui();
}

void MainWindow::on_urlPlainTextEdit_textChanged()
{
    updateGui();
}

void MainWindow::on_certLineEdit_textChanged(const QString &arg1)
{
    Q_UNUSED(arg1)
    updateGui();
}

void MainWindow::on_checkBox_toggled(bool checked)
{
    Q_UNUSED(checked)
    updateGui();
}

void MainWindow::on_urlListWidget_itemClicked(QListWidgetItem *item)
{
    ui->urlPlainTextEdit->setPlainText(item->text());
    updateGui();
}

void MainWindow::on_urlListWidget_itemDoubleClicked(QListWidgetItem *item)
{
    on_urlListWidget_itemClicked(item);
    on_pushButton_clicked();
}
