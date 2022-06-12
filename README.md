# intelligence-filter-misp

使用CIRCL.lu的公開情資做解析 <br>
https://www.circl.lu/doc/misp/feed-osint/ <br><br>
第一個執行程式

```python
python3 OSINT.py
```
### 程式步驟
1. 接收一筆情資後針對md5的value做擷取
2. 一筆情資有可能有多筆hash file，將其儲存在md5_file.txt
3. 讀取md5_file.txt裡的hash value
4. 將hash value丟到virustotal分析(加入自己的virustotal api key)
5. 判斷此情資的impact
6. 分析結果 => 是否歸類為Type 1 error
7. 建立type1Error_uuid.txt，儲存Type 1 error情資的uuid

- 執行完會產生md5_file.txt檔(相依於當前分析的情資)<br>
- 有type 1 error則會再建立type1Error_uuid.txt檔<br>

### 如何判斷Type 1 error
1. file hash上傳至virustotal分析，若此情資內過半(大於50%)file都沒有被其他防毒公司檢測為惡意，則為type 1 error
2. 情資內沒有檔案hash(md5)
3. Impact程度過小

第三點評估方法是參考此篇論文  
H. Griffioen, T. Booij, C. Doerr, “Quality evaluation of cyber threat
intelligence feeds,” in International Conference on Applied
Cryptography and Network Security, pp. 277‐296, 2020.
<br><br>
此篇論文提出四個feed評估指標
- Timeliness
- Sensitivity
- Originality
- Impact
  
### Impact
一筆情資應該會連結到「特定」的一個資安事件，如果此資安事件越明確且影響範圍越大，代表了此情資具有相當程度的「價值」，反之則代表對使用者而言情資沒有高的價值。

因此我選擇Impact這個指標來加入我的feed filter  ，透過feed內"info"這個標籤內的資料如"OSINT - DearCry ransomware (abusing Exchange Server)"來進行Google search，如果搜尋出來的數量過少（程式設定為五筆），則代表impact程度小，分析的情資沒有高的價值。
<br><br>
第二個執行程式
```python
python3 deleteEvent.py
```
1. 開啟MISP後在程式內填入misp key(for pymisp)
2. 根據執行OSINT.py後產生的type1Error_uuid.txt，刪除MISP對應的Event