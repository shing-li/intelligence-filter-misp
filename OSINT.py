from multiprocessing.sharedctypes import Value
from textwrap import indent
import requests
import urllib3
from bs4 import BeautifulSoup
from jsonpath_ng import jsonpath, parse

def creat_md5_list():
    # test file: 0165e5d7-51e6-4c2e-a382-1dd1e706f7bb.json
    urllib3.disable_warnings()
    r1 = requests.get("https://www.circl.lu/doc/misp/feed-osint/0165e5d7-51e6-4c2e-a382-1dd1e706f7bb.json", verify=False)
    #print(r1.status_code)

    intelli = r1.json()
    jsonpath1 = parse("Event.Object[*].Attribute[*].[type,value]")  #Event->Object->Attribute->type, value，解析Json第四層的type、Value
    uuid = intelli['Event']['uuid']
    #print(uuid)
    with open('temp.txt', 'a') as f:
        #f.write(uuid)
        for match1 in jsonpath1.find(intelli):  #creat a temp list
            print(match1.value)
            f.write(match1.value)
            f.write('\n')
    organize_list()
    return uuid

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
                hash_file = line[:-2]
                store.append(hash_file)
            line = f.readline()
            if line == '':
                flag1 = True
    
    with open('md5_file.txt', 'w') as f:
        print(store)
        for data in store:
            f.write(data)
            f.write('\n')

def vt_scan(uuid):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params1 = { 'apikey' : 'api'}
    checkFlag = False       #CheckFlag如果為真，代表此檔案未受過防毒檢測(不可信)
    checkList = list()      #情資內部可能有許多hash file，一一檢測並儲存
    count = 0               #positive數量
    positiveRatio = 0.0     #positive與total的比值

    with open('md5_file.txt', 'r') as f:
        print(uuid)
        for hash_file in f.readlines():
            hash_file = hash_file[:-2]
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
                print(data)
                print('='*200)
                print(data['positives'])
                print(data['total'])
    print('checkList is: '+checkList)
    for test in checkList:
        if test == True:
            count = count + 1 
    positiveRatio = count / len(checkList)
    print('The Positive Ratio is: {:.2f}%'.format(positiveRatio*100))

#def checkFalsePositive():


def main():
    uuid = creat_md5_list()
    #organize_list()
    vt_scan(uuid)

if __name__ == '__main__':
    main()