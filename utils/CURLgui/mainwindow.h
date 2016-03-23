#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();

    void on_postDataPlainTextEdit_textChanged();

    void on_comboBox_currentIndexChanged(const QString &arg1);

    void on_urlPlainTextEdit_textChanged();

    void on_certLineEdit_textChanged(const QString &arg1);

    void on_checkBox_toggled(bool checked);

    void on_urlListWidget_itemClicked(QListWidgetItem *item);

    void on_urlListWidget_itemDoubleClicked(QListWidgetItem *item);

private:
    QString cmd;
    QString hist_filename;
    Ui::MainWindow *ui;
    void loadTextFile();
    void updateGui();
};

#endif // MAINWINDOW_H
