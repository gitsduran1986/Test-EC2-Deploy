# -*- coding: utf-8 -*-
"""
Created on Thu Jul 23 05:57:46 2020

@author: duran
"""
import pandas as pd
import re
import sys 
import requests

blacklist_file = sys.argv[1]

def newline(c):
    """
    This function takes the output of pd.read(URL of new malicious cert report) and 
    converts into single line (as a df) to be appended to table of all malicious certs
    """
    
    values = {}
    for i in range(len(c[0])):
        values[c[0][0][i]] = c[0][1][i]
        
    for i in range(len(c[1].columns)):
        values[c[1].columns[i]] = c[1][c[1].columns[i]][0]
    
    df = pd.DataFrame(values.values()).transpose()
    df.columns = values.keys()

    return df

def get_new(SHA_BL,SSL_Blacklist):
    """
    This function searches checks for new malicious cert SHA1 hashes, if 
    there exist some one website and not in csv, then add them
    
    Takes a websites current list and our current list as input and returns a new
    SSL_blacklist dataframe
    """
    Base_URL = 'https://sslbl.abuse.ch/ssl-certificates/sha1/'
    new_SHA = []
    bl = SSL_Blacklist['SHA1 Fingerprint:'].tolist()
    for i in SHA_BL['SHA1']:
        if i not in bl:
            new_SHA.append(i)
    
    if len(new_SHA) == 0:
        
        print('Result: No New Certs on Blacklist')
        
    else:
        
        for i in range(0,len(new_SHA)):
            Cert_URL = Base_URL+new_SHA[i]

            pd_read = pd.read_html(requests.get(Cert_URL).text)
            if len(SSL_Blacklist) == 0:
                SSL_Blacklist = newline(pd_read)
            else:
                SSL_Blacklist = pd.concat([SSL_Blacklist,newline(pd_read)])
                
        print("Result: {} new certificate(s) added to SSL_Blacklist".format(len(new_SHA)))
    return SSL_Blacklist
    
def splitCertString(string,column_ref):
    """
    This function takes a string from the CERTAUTHORITY_ISSUER or CERTAUTHORITY_SUBJECT columns and 
    returns a dictionary of key-value pair
    """

    string = re.sub('/',',',string)
    string = re.sub(' ','',string)
    string = re.sub('Email','emailAddress',string)

    
    use = ['C','CN','L','O','OU','ST','emailAddress','unstructuredName','serialNumber']
    
    if len(string.split(',')) == 1:
        d = {column_ref+'_CN':string}
    else:
        d = {}
        for i in string.split(','):
            if len(i.split('=')) == 1:
                d[column_ref+'_CN'] = i
            elif i.split('=')[0] in use:
                d[column_ref+'_'+i.split('=')[0]] = i.split('=')[1]

    return d


def main():
    # Grab websites current list blacklist csv with SHA1 codes
    SHA_BL = pd.read_csv('https://sslbl.abuse.ch/blacklist/sslblacklist.csv',header=8)
    SHA_BL = SHA_BL[:-1]
    
    #read in our local black list
    SSL_Blacklist = pd.read_csv(blacklist_file)

    #ignore index and parsed CA strings
    SSL_Blacklist = SSL_Blacklist.iloc[:, 1:-15]
    
    
    #run get new (which checks for new certs and updates blacklist)
    SSL_Blacklist = get_new(SHA_BL,SSL_Blacklist)
    SSL_Blacklist = SSL_Blacklist.reset_index(drop=True)

    #parse the strings of certifications to make them more easily compared in notebook
    issuer_cols = []
    subject_cols = []
    
    for i in range(len(SSL_Blacklist['Certificate Common Name (CN):'])):
        issuer_cols.append(splitCertString(str(SSL_Blacklist['Issuer Distinguished Name (DN):'].iloc[i,]),"CA_ISSUER"))
        subject_cols.append(splitCertString(str(SSL_Blacklist['Certificate Common Name (CN):'].iloc[i,]),"CA_SUBJECT"))
                           
    issuer_df = pd.DataFrame.from_records(issuer_cols)                    
    subject_df = pd.DataFrame.from_records(subject_cols)
    
    
    SSL_Blacklist_Split = pd.concat([SSL_Blacklist, issuer_df,subject_df], axis=1)
    
    #create new csv or overwrite existing csv with updated list
    SSL_Blacklist_Split.to_csv(blacklist_file)
    
if __name__=="__main__":
    main()