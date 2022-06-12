import os
import requests
import urllib3
from bs4 import BeautifulSoup
from jsonpath_ng import jsonpath, parse
from googlesearch import search
import ssl
ssl._create_default_https_context = ssl._create_unverified_context  #unverifiy ssl

vt_api_key = '42186906bac669307672ba33a39ad0f891d820c50539d842881cd2d6b6cad923' #virustotal api key

def creat_md5_list():
    # test file1: 0165e5d7-51e6-4c2e-a382-1dd1e706f7bb.json
    # test file2: 4b475a5f-ea47-4f2f-aea3-d8ba9bd1b6b6.json
    urllib3.disable_warnings()
    r1 = requests.get("https://www.circl.lu/doc/misp/feed-osint/0165e5d7-51e6-4c2e-a382-1dd1e706f7bb.json", verify=False)
    #print(r1.status_code)

    intelli = r1.json()
    jsonpath1 = parse("Event.Object[*].Attribute[*].[type,value]")  #Event->Object->Attribute->type, value，解析Json第四層的type、Value
    uuid = intelli['Event']['uuid']
    osintName = intelli['Event']['info']
    #print(uuid)
    with open('temp.txt', 'w') as f:
        #f.write(uuid)
        for match1 in jsonpath1.find(intelli):  #creat a temp list
            #print(match1.value)
            f.write(match1.value)
            f.write('\n')
    organize_list()
    return uuid, osintName

def organize_list():
    store = list()                  #存md5的value
    with open('temp.txt', 'r') as f:
        line = f.readline()
        flag1 = False
        while flag1 is False:       #擷取md5的value
            #print(type(line))
            if line == 'md5\n':     #md5的下一行為hash value
                print('md5 yes')
                line = f.readline()
                hash_file = line[:-1]
                store.append(hash_file)
            line = f.readline()
            if line == '':
                flag1 = True
    
    with open('md5_file.txt', 'w') as f:    #create a file that store md5's hash value
        #print(store)
        for data in store:
            f.write(data)
            f.write('\n')

    if os.path.exists("temp.txt"):  #delete temp.txt
        os.remove("temp.txt")

def vt_scan(uuid, osintName):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params1 = { 'apikey' : vt_api_key}  
    checkFlag = False                   #CheckFlag如果為真，代表此檔案未受過防毒檢測(不可信)
    checkList = list()                  #情資內部可能有許多hash file，一一檢測並儲存
    falsePositiveCount = 0              #此筆情資內部檔案hash的false positive數量 
    falsePositiveRatio = 0.0            #falsePositiveCount / hash的數量
    isType1Error = False
    print('uuid: ')
    print(uuid)
    with open('md5_file.txt', 'r') as f:
        for hash_file in f.readlines():
            hash_file = hash_file[:-1]
            print("The file hash is: "+hash_file)
            params1['resource'] = hash_file   
            response = requests.get(url, params=params1)
            data = response.json()
            if data['response_code'] == 0:
                print('The file is not exist in VirusToal!')
                checkFlag = True
                checkList.append(checkFlag)
                checkFlag = False
            else:
                #print(data)
                print(data['positives'])
                print(data['total'])
                print('='*200)
                checkList.append(checkFlag)
    print('Checklist is: ')
    print(checkList)
    for test in checkList:
        if test == True:
            falsePositiveCount = falsePositiveCount + 1 
    try:
        falsePositiveRatio = falsePositiveCount / len(checkList)
        print('The Positive Ratio is: {:.2f}%'.format(falsePositiveRatio*100))
    except:
        isType1Error = True    #代表情資內沒有md5檔案
        print('No md5 file in this feed!')
    #print('positiveRatio is: '+str(falsePositiveRatio))
    if falsePositiveRatio > 0.5: #如果>0.5，代表此feed內的hash file有過半沒有經過防毒公司檢測為惡意
        isType1Error = True
    
    googleSearchQuery = "\""+osintName+"\"" #使用""將搜尋內容包起來
    googleSearchCount = 0
    print('Google search '+osintName)
    for i in search(googleSearchQuery, num=5, pause=2.0): 
        print(i)
        googleSearchCount = googleSearchCount + 1
    if googleSearchCount < 5:   #google搜尋結果少於五筆
        print("This feed is Low impact!")
        isType1Error = True

    if isType1Error:    #經過三個判斷，如果為真則記錄feed的uuid在error file
        writeErrorFile(uuid)
        print('='*100)
        print('This feed is Type 1 error!')

def writeErrorFile(uuid):
    with open('type1Error_uuid.txt', 'a') as f:
        f.write(uuid)
        f.write('\n')

def main():
    uuid, osintName = creat_md5_list()
    #organize_list()
    #uuid = '4b475a5f-ea47-4f2f-aea3-d8ba9bd1b6b6'
    vt_scan(uuid, osintName)

if __name__ == '__main__':
    main()