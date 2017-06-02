#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QListWidgetItem>
#include <QDebug>
#include <QFileDialog>
#include <QMessageBox>
#include <QTreeWidgetItem>
#include <QLabel>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("cutePE");
    ui->menuBar->setVisible(false);
    setFixedSize(this->width(),this->height());
    bottom_label=new QLabel("",this);
    ui->statusBar->addWidget(bottom_label);

    //toolbar
    QAction* open_action = new QAction("Open",this);
    open_action->setIcon(QIcon(":/res/open.png"));
    ui->mainToolBar->addAction(open_action);
    QAction* about_action = new QAction("About",this);
    about_action->setIcon(QIcon(":/res/question.png"));
    ui->mainToolBar->addAction(about_action);

    //界面左：treeWidget
    ui->treeWidget->setColumnCount(1);
    ui->treeWidget->setHeaderHidden(true);

    QTreeWidgetItem *dos_header = new QTreeWidgetItem(ui->treeWidget);
    dos_header->setText(0,"IMAGE_DOS_HEADER");
    QTreeWidgetItem *dos_stub = new QTreeWidgetItem(ui->treeWidget);
    dos_stub->setText(0,"MS-DOS Stub Program");
    QTreeWidgetItem *nt_header = new QTreeWidgetItem(ui->treeWidget);
    nt_header->setText(0,"IMAGE_NT_HEADERS32");
    section_table = new QTreeWidgetItem(ui->treeWidget);
    section_table->setText(0,"SectionTable");

    QTreeWidgetItem *mz_signature = new QTreeWidgetItem(nt_header,QStringList(QString("Signature")));
    nt_header->addChild(mz_signature);
    QTreeWidgetItem *file_header = new QTreeWidgetItem(nt_header,QStringList(QString("IMAGE_FILE_HEADER")));
    nt_header->addChild(file_header);
    QTreeWidgetItem *optinal_header = new QTreeWidgetItem(nt_header,QStringList(QString("IMAGE_OPTIONAL_HEADER32")));
    QTreeWidgetItem *stand_coff_field = new QTreeWidgetItem(optinal_header,QStringList(QString("Standard COFF Fields")));
    nt_header->addChild(stand_coff_field);
    QTreeWidgetItem *win_spec_field = new QTreeWidgetItem(optinal_header,QStringList(QString("Windows Specific Fields")));
    nt_header->addChild(win_spec_field);
    QTreeWidgetItem *data_dir = new QTreeWidgetItem(optinal_header,QStringList(QString("Data Directories")));
    nt_header->addChild(data_dir);
    nt_header->addChild(optinal_header);

    rootList.append(dos_header);
    rootList.append(dos_stub);
    rootList.append(nt_header);
    rootList.append(section_table);

    ui->treeWidget->expandAll();


    //界面右：tableWidget
    defaultInitLayoutRight();


    //绑定信号槽
    connect(ui->treeWidget,SIGNAL(itemClicked(QTreeWidgetItem*,int)),this,SLOT(tableWidget_update(QTreeWidgetItem*,int)));
    connect(ui->mainToolBar,SIGNAL(actionTriggered(QAction*)),this,SLOT(toolbar_clicked(QAction*)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::defaultInitLayoutRight()
{
    QStringList str_list;
    str_list.push_back(QString("File offset"));
    str_list.push_back(QString("Data"));
    str_list.push_back(QString("Description"));
    initLayoutRight(str_list);
}

void MainWindow::initLayoutRight(QStringList& str_list)
{
    ui->tableWidget->setColumnCount(str_list.count());
    ui->tableWidget->setHorizontalHeaderLabels(str_list);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);    //x先自适应宽度
    for(int i=0;i<str_list.count();i++){
        ui->tableWidget->horizontalHeader()->setSectionResizeMode(i, QHeaderView::ResizeToContents);     //然后设置要根据内容使用宽度的列
    }
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
}

void MainWindow::tableWidget_update(QTreeWidgetItem *clicked_tree_item, int)
{
    if(raw_bytes_string.size()){
        QString item_label_clicked=clicked_tree_item->text(0);
        if(item_label_clicked=="IMAGE_DOS_HEADER"){
            defaultInitLayoutRight();
            ui->tableWidget->setRowCount(2);

            QTableWidgetItem *table_item = new QTableWidgetItem(QString("00"));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(0x00,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,1,table_item);
            table_item = new QTableWidgetItem(QString("e_magic"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(0,2,table_item);

            table_item = new QTableWidgetItem(QString("3C"));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(0x3c,4,true)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,1,table_item);
            table_item = new QTableWidgetItem(QString("e_lfanew"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(1,2,table_item);
        }else if(item_label_clicked=="MS-DOS Stub Program"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(0);
        }else if(item_label_clicked=="IMAGE_NT_HEADERS32"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(0);
        }else if(item_label_clicked=="Signature"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(1);

            QTableWidgetItem *table_item = new QTableWidgetItem(QString::number(pe_header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(pe_header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,1,table_item);
            table_item = new QTableWidgetItem(QString("Signature"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(0,2,table_item);
        }else if(item_label_clicked=="IMAGE_FILE_HEADER"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(7);
            long long header_offset=pe_header_offset+4;

            QTableWidgetItem *table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,1,table_item);
            table_item = new QTableWidgetItem(QString("Machine"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(0,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,1,table_item);
            table_item = new QTableWidgetItem(QString("NumberOfSections"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(1,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,1,table_item);
            table_item = new QTableWidgetItem(QString("TimeDateStamp"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(2,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,1,table_item);
            table_item = new QTableWidgetItem(QString("PointerToSymbolTable"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(3,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(4,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(4,1,table_item);
            table_item = new QTableWidgetItem(QString("NumberOfSymbols"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(4,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(5,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(5,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfOptionalHeader"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(5,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(6,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(6,1,table_item);
            table_item = new QTableWidgetItem(QString("Characteristics"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(6,2,table_item);
        }else if(item_label_clicked=="IMAGE_OPTIONAL_HEADER32"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(0);
        }else if(item_label_clicked=="Standard COFF Fields"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(9);
            long long header_offset=pe_header_offset+0x18;

            QTableWidgetItem *table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,1,table_item);
            table_item = new QTableWidgetItem(QString("Magic"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(0,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,1,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,1,table_item);
            table_item = new QTableWidgetItem(QString("MajorLinkerVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(1,2,table_item);
            header_offset+=1;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,1,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,1,table_item);
            table_item = new QTableWidgetItem(QString("MinorLinkerVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(2,2,table_item);
            header_offset+=1;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfCode"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(3,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(4,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(4,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfInitializedData"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(4,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(5,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(5,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfUninitializedData"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(5,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(6,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(6,1,table_item);
            table_item = new QTableWidgetItem(QString("AddressOfEntryPoint"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(6,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(7,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(7,1,table_item);
            table_item = new QTableWidgetItem(QString("BaseOfCode"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(7,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(8,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(8,1,table_item);
            table_item = new QTableWidgetItem(QString("BaseOfData"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(8,2,table_item);
            header_offset+=4;
        }else if(item_label_clicked=="Windows Specific Fields"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(21);
            long long header_offset=pe_header_offset+0x34;

            QTableWidgetItem *table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,1,table_item);
            table_item = new QTableWidgetItem(QString("ImageBase"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(0,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,1,table_item);
            table_item = new QTableWidgetItem(QString("SectionAlignment"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(1,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,1,table_item);
            table_item = new QTableWidgetItem(QString("FileAlignment"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(2,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,1,table_item);
            table_item = new QTableWidgetItem(QString("MajorOperatingSystemVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(3,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(4,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(4,1,table_item);
            table_item = new QTableWidgetItem(QString("MinorOperatingSystemVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(4,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(5,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(5,1,table_item);
            table_item = new QTableWidgetItem(QString("MajorImageVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(5,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(6,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(6,1,table_item);
            table_item = new QTableWidgetItem(QString("MinorImageVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(6,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(7,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(7,1,table_item);
            table_item = new QTableWidgetItem(QString("MajorSubsystemVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(7,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(8,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(8,1,table_item);
            table_item = new QTableWidgetItem(QString("MinorSubsystemVersion"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(8,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(9,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(9,1,table_item);
            table_item = new QTableWidgetItem(QString("Win32VersionValue"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(9,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(10,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(10,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfImage"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(10,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(11,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(11,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfHeaders"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(11,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(12,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(12,1,table_item);
            table_item = new QTableWidgetItem(QString("CheckSum"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(12,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(13,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(13,1,table_item);
            table_item = new QTableWidgetItem(QString("Subsystem"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(13,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(14,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,2,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(14,1,table_item);
            table_item = new QTableWidgetItem(QString("DllCharacteristics"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(14,2,table_item);
            header_offset+=2;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(15,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(15,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfStackReserve"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(15,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(16,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(16,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfStackCommit"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(16,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(17,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(17,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfHeapReserve"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(17,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(18,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(18,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfHeapCommit"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(18,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(19,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(19,1,table_item);
            table_item = new QTableWidgetItem(QString("LoaderFlags"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(19,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(20,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(20,1,table_item);
            table_item = new QTableWidgetItem(QString("NumberOfRvaAndSizes"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(20,2,table_item);
        }else if(item_label_clicked=="Data Directories"){defaultInitLayoutRight();
            ui->tableWidget->setRowCount(4);
            long long header_offset=pe_header_offset+0x78;

            QTableWidgetItem *table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(0,1,table_item);
            table_item = new QTableWidgetItem(QString("ExportTable"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(0,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(1,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfExportTable"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(1,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(2,1,table_item);
            table_item = new QTableWidgetItem(QString("ImportTable"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(2,2,table_item);
            header_offset+=4;

            table_item = new QTableWidgetItem(QString::number(header_offset, 16).toUpper());
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,0,table_item);
            table_item = new QTableWidgetItem(QString::fromStdString(getBytesFromRAW(header_offset,4,false)));
            table_item->setTextAlignment(Qt::AlignRight);
            ui->tableWidget->setItem(3,1,table_item);
            table_item = new QTableWidgetItem(QString("SizeOfImportTable"));
            table_item->setTextAlignment(Qt::AlignCenter);
            ui->tableWidget->setItem(3,2,table_item);
            header_offset+=4;
        }else if(item_label_clicked=="SectionTable"){
            //读取Section个数
            string sections_num=getBytesFromRAW(pe_header_offset+0x06,2,true);
            long long section_num=hexString2LongLong(sections_num);
            //定位到SectionTable
            string optional_header_size=getBytesFromRAW(pe_header_offset+0x14,2,true);
            long long optiona_header_size=hexString2LongLong(optional_header_size);
            long long section_table_offset=pe_header_offset+0x18+optiona_header_size;
            //读取SectionTable中的name，并更新界面右边显示
            QStringList str_list;
            str_list.push_back(QString("Name"));
            str_list.push_back(QString("VirtualSize"));
            str_list.push_back(QString("VitualAddress(RVA)"));
            str_list.push_back(QString("SizeOfRawData"));
            str_list.push_back(QString("PointerToRawData"));
            str_list.push_back(QString("Characteristics"));
            initLayoutRight(str_list);
            ui->tableWidget->setRowCount(section_num);

            string section_name;
            string section_virtualsize;
            string section_virtualaddress;
            string section_sizeofrawdata;
            string section_pointertorawdata;
            string section_chara;
            for(int i=0;i<section_num;i++){
                string section_name_bytes=getBytesFromRAW(section_table_offset,8,false);
                section_name=getSectionNameStr(section_name_bytes);

                section_virtualsize=getBytesFromRAW(section_table_offset+0x08,4,false);
                section_virtualaddress=getBytesFromRAW(section_table_offset+0x0c,4,false);
                section_sizeofrawdata=getBytesFromRAW(section_table_offset+0x10,4,false);
                section_pointertorawdata=getBytesFromRAW(section_table_offset+0x14,4,false);
                section_chara=getBytesFromRAW(section_table_offset+0x24,4,false);

                QTableWidgetItem *table_item = new QTableWidgetItem(QString::fromStdString(section_name));
                table_item->setTextAlignment(Qt::AlignCenter);
                ui->tableWidget->setItem(i,0,table_item);

                table_item = new QTableWidgetItem(QString::fromStdString(section_virtualsize));
                table_item->setTextAlignment(Qt::AlignRight);
                ui->tableWidget->setItem(i,1,table_item);

                table_item = new QTableWidgetItem(QString::fromStdString(section_virtualaddress));
                table_item->setTextAlignment(Qt::AlignRight);
                ui->tableWidget->setItem(i,2,table_item);

                table_item = new QTableWidgetItem(QString::fromStdString(section_sizeofrawdata));
                table_item->setTextAlignment(Qt::AlignRight);
                ui->tableWidget->setItem(i,3,table_item);

                table_item = new QTableWidgetItem(QString::fromStdString(section_pointertorawdata));
                table_item->setTextAlignment(Qt::AlignRight);
                ui->tableWidget->setItem(i,4,table_item);

                table_item = new QTableWidgetItem(QString::fromStdString(section_chara));
                table_item->setTextAlignment(Qt::AlignRight);
                ui->tableWidget->setItem(i,5,table_item);

                section_table_offset+=0x28;
            }
        }
    }
}

//获取raw_bytes_string中addr起始的bytes_length字节。is_reversed指定是否逆序输出字节
string MainWindow::getBytesFromRAW(long long addr,long long bytes_length,bool is_reversed){
    string bytes_string;
    if(is_reversed){//小端机逆序输出地址，方便后续操作
        for(int i=addr+bytes_length-1;i>addr-1;i--){
            bytes_string.append(raw_bytes_string[i]);
        }
    }else{
        for(int i=addr;i<addr+bytes_length;i++){
            bytes_string.append(raw_bytes_string[i]);
        }
    }

    return bytes_string;
}

long long MainWindow::hexString2LongLong(string& hexStr)
{
    hexStr=hexStr.erase(0,hexStr.find_first_not_of("0"));//去掉000000E0前面的000000
    return strtoll(hexStr.c_str(),NULL,16);
}

string MainWindow::getSectionNameStr(string& section_name_bytes)
{
    string name_str;

    int i=0;
    while(section_name_bytes[i]!='0' || section_name_bytes[i+1]!='0'){
        string one_byte;
        one_byte.append(1,section_name_bytes[i]);
        one_byte.append(1,section_name_bytes[i+1]);
        char str=(char)hexString2LongLong(one_byte);
        name_str.append(1,str);
        i+=2;
    }

    return name_str;
}

void MainWindow::toolbar_clicked(QAction*action)
{
    if(action->text()=="Open"){
        QString path = QFileDialog::getOpenFileName(this,
                                                    "Open File",
                                                    ".",
                                                    "Text Files(*.exe *.dll *.ocx *.sys *.com)");
        if(!path.isEmpty()){
            ui->tableWidget->setRowCount(0);//关闭界面右显示

            QFile file(path);
            if (!file.open(QIODevice::ReadOnly)) {
                QMessageBox::warning(this, "Read File",
                                     tr("Cannot open file:\n%1").arg(path));
                return;
            }
            QByteArray raw_bytes;
            raw_bytes = file.readAll();
            file.close();
            string byte_string;
            vector <string>().swap(raw_bytes_string);
            for(int i=0;i<raw_bytes.count();i++){
                byte_string=QString::number(raw_bytes[i]&0x000000000000ff, 16).toUpper().toStdString();
                if(byte_string.length()==1){
                    byte_string="0"+byte_string;
                }
                raw_bytes_string.push_back(byte_string);
            }
            //判断是否为PE文件
            if(raw_bytes_string.size()>0x3f && raw_bytes_string[0]=="4D" && raw_bytes_string[1]=="5A"){//MZ
                string pe_header_offset_string=getBytesFromRAW(0x3c,4,true);
                pe_header_offset=hexString2LongLong(pe_header_offset_string);
                string pe_header_first_4_bytes=getBytesFromRAW(pe_header_offset,4,false);
                if(pe_header_first_4_bytes=="50450000"){//PE\0\0
                    bottom_label->setText(tr("%1 Loaded.").arg(path));

                }else{
                    QMessageBox::warning(this, "File Error",
                                         "Ops,it is NOT a PE file!");
                    bottom_label->setText("");
                }
            }else{
                QMessageBox::warning(this, "File Error",
                                     "Ops,it is NOT a PE file!");
                bottom_label->setText("");
            }
        }
    }else if(action->text()=="About"){
        QMessageBox::information(this,"cutePE's MAIN bug","<div>Why could't cutePE load a large PE??? <br><br> Eh, cause spenghui "
                                                      "uses a stack variable to store all the file bytes, so it's easy to "
                                                      "cause a memory crash...<br><br> The source code is <a href=\"https://github.com/spenghui/cutePE32\">here</a>.<br><br>————by spenghui in June 2,2017</div>");
    }
}
