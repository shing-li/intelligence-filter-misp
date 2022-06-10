from pymisp import ExpandedPyMISP
misp_url = 'https://localhost/'
misp_key = '' # The MISP auth key can be found on the MISP web interface>
misp_verifycert = False

if __name__ == '__main__':

    with open('type1Error_uuid.txt', 'r') as f:
        uuid_read = f.readline()[:-1]
    #print(uuid_read)
    
    mispObj1 = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    mispResult = mispObj1.search(uuid=uuid_read)    #return a list that contains a dict
    eventID = mispResult[0]['Event']['id']
    print('event id is: '+str(eventID))

    eventResult = mispObj1.delete_event(eventID)
    print(eventResult)