def getcreds():
    home = expanduser("~")
    credslo = home+'\.aws\credentials'
    configParser = configparser.RawConfigParser()
    configParser.read(credslo)
    ### account is fixed as of change the variable when needed
    ## get the specific account creds from user
    ## account numer input future extension
    condict = dict(configParser.items())
    for keys in condict:
        if keys.split('-')[0] == '130312249203':
            creddict = dict(condict[keys])
            #print (creddict)  ##debug
            break
    return creddict
