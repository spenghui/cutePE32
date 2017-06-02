#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidgetItem>
#include <iostream>
#include <vector>
#include <QLabel>
using namespace std;
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QList<QTreeWidgetItem *> rootList;
    vector <string> raw_bytes_string;
    long long pe_header_offset;
    QTreeWidgetItem *section_table;
    QLabel* bottom_label;

    void defaultInitLayoutRight();
    void initLayoutRight(QStringList &str_list);
    string getBytesFromRAW(long long addr,long long bytes_length,bool is_reversed);
    long long hexString2LongLong(string& hexStr);
    string getSectionNameStr(string &section_name_bytes);

private slots:
    void tableWidget_update(QTreeWidgetItem*, int);
    void toolbar_clicked(QAction *action);
};

#endif // MAINWINDOW_H
