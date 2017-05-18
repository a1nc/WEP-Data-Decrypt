#include "mainwindow.h"
#include <QApplication>
#include <QObject>
#include <QFile>
#include <QString>
#include <QDebug>

const QString FILE_PATH("C:\\QtProject\\ExcelRead\\test.csv");

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    /*write a csv file*/
//    QString line_0("yangpeng,id031430330,macabababababab\n");
//    QString line_1("zhangsan,id031430331,macabababababab\n");
//    QString line_2("lisi,id031430332,macabababababab\n");
//    QFile csvFile(FILE_PATH);
//    if(csvFile.open(QIODevice::ReadWrite))
//    {
//        csvFile.write(line_0.toStdString().data());
//        csvFile.write(line_1.toStdString().data());
//        csvFile.write(line_2.toStdString().data());
//        csvFile.close();
//    }

    /*read a csv file*/
    QFile csvFileOpen(FILE_PATH);
    QStringList csvList;
    csvList.clear();
    if(csvFileOpen.open(QIODevice::ReadWrite))
    {
        QTextStream stream(&csvFileOpen);
        while(!stream.atEnd())
        {
            csvList.push_back(stream.readLine());
        }
        csvFileOpen.close();
    }

    Q_FOREACH(QString str,csvList)
    {
        qDebug()<<"ID: "<<str.split(',').at(1);
        qDebug()<<"MAC: "<<str.split(',').at(2);
    }

    return a.exec();
}
