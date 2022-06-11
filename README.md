# intelligence-filter-misp

使用CIRCL.lu的公開情資做解析
https://www.circl.lu/doc/misp/feed-osint/

```
python3 OSINT.py
```
1. 接收一筆情資後針對md5的value做擷取
2. 一筆情資有可能有多筆hash file，將其儲存在md5_file.txt
3. 讀取md5_file.txt裡的hash value
4. 將hash value丟到virustotal分析(加入自己的virustotal api key)
5. 若virustotal沒有相關的資料 => 歸類為Type 1 error
6. 建立type1Error_uuid.txt，儲存Type 1 error的uuid

執行完會產生md5_file.txt檔(相依於當前分析的情資)
Virustotal：
有分析資料 => 情資可信
無分析資料 => Type 1 error => 建立type1Error_uuid.txt檔(該情資的唯一識別碼uuid)

```
python3 deleteEvent.py
```
1. 開啟MISP後在程式內填入misp key(for pymisp)
2. 根據執行OSINT.py後產生的type1Error_uuid.txt，刪除MISP對應的Event