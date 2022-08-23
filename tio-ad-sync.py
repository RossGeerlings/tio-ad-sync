#!/usr/bin/env python3
#
# Tio-AD-Sync 
# 
# Author:
# Ross Geerlings <rjgeer at umich.edu>,  <ross at seekerdlp.com>
#
# Special thanks to:
# Neamen Negash <nnegash at umich.edu> (Contributions re: network syncing)
# Dale Fay <dalef at umich.edu> (Contributions re: full user names from AD) 
#
# Tio-AD-Sync uses the request_data method from Casey Reid's Navi, which is
# available on GitHub under the GPL-3.0 License at 
# https://github.com/packetchaos/navi.
#
#
#
# Tio-AD-Sync is licensed under the terms of the GPL-3.0 license.
#
# ==========================================================================



import argparse
import configparser
import csv
import gnupg
import os
import pprint
import random
import re
import requests
import string 
import sys
import time
from json import JSONDecodeError
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError
from tenable.io import TenableIO
from uuid import UUID



parser = argparse.ArgumentParser()
parser.add_argument('--agent-group-create', "-a", dest='UserGroup_With_Access_to_All_AgentGroups', default=None, \
                    help='Optional, adds an agent group by the same name as'\
                    ' a user group and sets permissions. Adds permissions for an admin group you specify here (required),'\
                    ' as well as the user group by the same name.')
parser.add_argument('--config-file', "-c", dest='config_file', help='Config File')

args = parser.parse_args()
UserGroup_With_Access_to_All_AgentGroups = args.UserGroup_With_Access_to_All_AgentGroups

try:
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    scanconfig = configparser.RawConfigParser()
    f = open(args.config_file)
    scanconfig.read_file(f)
    f.close()
except IOError as err:
    exit(err)

gpg = gnupg.GPG(gnupghome=scanconfig.get("IO", "gpghome"))
access_file=scanconfig.get("IO", "access_file")
secret_file=scanconfig.get("IO", "secret_file")
net_map_file=scanconfig.get("IO", "net_map_file")
ad_user_name = scanconfig.get("IO", "ad_user_name")
ad_cred_file=scanconfig.get("IO", "ad_cred_file")
ad_dc_name = scanconfig.get("IO", "ad_dc_name") 
ad_domain_name = scanconfig.get("IO", "ad_domain_name")  
ad_groups_ou = scanconfig.get("IO", "ad_groups_ou")  
ad_base_dn = scanconfig.get("IO", "ad_base_dn")  
unmanaged_users = scanconfig.get("IO", "ad_domain_name").split(",")

access_f=open(access_file)
access_gpg=access_f.read()
access_key=str(gpg.decrypt(access_gpg)).rstrip()
secret_f=open(secret_file)
secret_gpg=secret_f.read()
secret_key=str(gpg.decrypt(secret_gpg)).rstrip()

ad_cred_f=open(ad_cred_file)
ad_cred_gpg=ad_cred_f.read()
ad_acct_pw=str(gpg.decrypt(ad_cred_gpg)).rstrip()

headers = {'Content-type': 'application/json', 'user-agent': 'Tio-ADSync-Script', 
           'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}



def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = "https://cloud.tenable.com"

    # check for params and set to None if not found
    try:
        params = kwargs['params']
    except KeyError:
        params = None

    # check for a payload and set to None if not found
    try:
        payload = kwargs['payload']
    except KeyError:
        payload = None

    #Replacement for Navi grab_headers
    gh_header_equivalent = {'Content-type': 'application/json', 'user-agent': 'UM-ADSync-Script', 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}

    # Retry the download three times
    for x in range(1, 3):
        try:
            r = requests.request(method, url + url_mod, headers=gh_header_equivalent, params=params, json=payload, verify=True)
            if r.status_code == 200:
                return r.json()

            if r.status_code == 202:
                # This response is for some successful posts.
                print("\nSuccess!\n")
                break
            elif r.status_code == 404:
                print('\nCheck your query...I can\'t find what you\'re looking for {}'.format(r))
                return r.json()
            elif r.status_code == 429:
                print("\nToo many requests at a time...\n{}".format(r))
                break
            elif r.status_code == 400:
                print("\nThe object you tried to create may already exist\n")
                print("If you are changing scan ownership, there is a bug where 'empty' scans won't be moved")
                break
            elif r.status_code == 403:
                print("\nYou are not authorized! You need to be an admin\n{}".format(r))
                break
            elif r.status_code == 409:
                print("API Returned 409\n If you are changing permissions, it could indicate a duplicate request\n")
                break
            elif r.status_code == 504:
                print("\nOne of the Threads and an issue during download...Retrying...\n{}".format(r))
                break
            else:
                print("Something went wrong...Don't be trying to hack me now {}".format(r))
                break
        except ConnectionError:
            print("Check your connection...You got a connection error. Retying")
            continue
        except JSONDecodeError:
            print("Download Error or User enabled / Disabled ")
            continue



if __name__ == '__main__':

    os.chdir(os.path.dirname(os.path.abspath(__file__))) #Consistent location for Navi DB, in script dir

    tio = TenableIO(access_key, secret_key)
    gpg = gnupg.GPG(gnupghome=scanconfig.get("Reports", "gpghome"))
    all_chars = string.ascii_letters + string.digits + string.punctuation
    dADGroups = {}
    dADUserToName = {}
    dUserGroupUUID = {}
    lADUsers = []
    lIAUnit = []   #Names of all units for which we have AD groups
    lTioUGNames = []

    # Group names are used at command line for Navi, avoiding command injection. 
    # '&' is being used out of necessity, and subsequently replaced with 'and'.
    AllowedGroupNameCharsReg = re.compile('[^0-9a-zA-Z\- ()&]') 



    ########################################################################################################################
    # Get current user and group info from Tenable.io  
    ########################################################################################################################
    lAllTioUsers = tio.users.list()  #Tenable.io users and properties
    lUserGroups = tio.groups.list()  #Tenable.io groups and properties 

    # Simple list of user group names in T.io
    for dUserGroup in lUserGroups:
        lTioUGNames.append(dUserGroup["name"])

    # Get usergroup to uuid mapping.
    for user_group in lUserGroups:
        dUserGroupUUID[str(user_group['name'])] = user_group['uuid']
        if UserGroup_With_Access_to_All_AgentGroups != None:
            if str(user_group['name']) == UserGroup_With_Access_to_All_AgentGroups:
                iAdminUserGroupID = user_group['id'] 

    # At this time, this script makes it mandatory to define a "central" user group w/ access to any agent group it creates.
    # This is in addition to like-named user groups, which will also be given access.
    if UserGroup_With_Access_to_All_AgentGroups != None:
        if 'iAdminUserGroupID' not in locals():
            print('The admin user group name you specified was not found in among Tenable.io groups.  Exiting.') 
            exit(0)
            


    #########################################################################################################################
    # Read AD groups. Get members of each group with prefix. Make a dictionary like <groupname,[member_list]>
    #########################################################################################################################
    print("Reading AD groups...") 

    server = Server(ad_dc_name, get_info=ALL)
    conn = Connection(server, user='{}\\{}'.format(ad_domain_name, ad_user_name), password=ad_acct_pw, authentication=NTLM,
                      auto_bind=True)
    conn.search(ad_groups_ou.format(ad_domain_name), 
                '(&(objectclass=group)(name=io-*))', attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])

    for oGroup in sorted(conn.entries):
        try:
            desc = oGroup.description
        except LDAPCursorError:
            desc = ""
        sADGroupName = str(oGroup.cn)[3:]
        sADGroupName = AllowedGroupNameCharsReg.sub('',sADGroupName.replace('&','and'))
        lIAUnit.append(sADGroupName)

        try:
            #First go through and get each USER in the members, and add directly to membership.
            for sUserDN in oGroup.member:
                conn2 = Connection(server, user='{}\\{}'.format(ad_domain_name, ad_user_name), password=ad_acct_pw, 
                                   authentication=NTLM,auto_bind=True)
                conn2.search(ad_base_dn.format(ad_domain_name), 
                             '(&(objectclass=user)(distinguishedName=%s))' % sUserDN,
                             attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
                for oUser in sorted(conn2.entries):
                    sUser = str(oUser.userPrincipalName).lower()
                    if sADGroupName in dADGroups.keys():
                        dADGroups[sADGroupName].append(sUser)
                    else:
                        dADGroups[sADGroupName] = [sUser]
                    try:
                        if sUser not in dADUserToName.keys():
                            dADUserToName[sUser] = str(oUser.sn) + "," + str(oUser.GivenName)
                    except:
                        print("Problem getting first and last name for user: %s" % sUser)

            #Grab all groups within the main group, add their direct members (these are the groups controlled by units) 
            for sGroupDN in oGroup.member:
                conn2.search(ad_base_dn.format(ad_domain_name), 
                             '(&(objectclass=group)(distinguishedName=%s))' % sGroupDN,
                             attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
                for oNestedGroup in sorted(conn2.entries):
                    try:
                        desc = oGroup.description
                    except LDAPCursorError:
                        desc = ""
                    for sNestedUserDN in oNestedGroup.member:
                        conn3 = Connection(server, user='{}\\{}'.format(ad_domain_name, ad_user_name),password=ad_acct_pw,
                                           authentication=NTLM,auto_bind=True)
                        conn3.search(ad_base_dn.format(ad_domain_name), 
                                     '(&(objectclass=user)(distinguishedName=%s))' % sNestedUserDN,
                                     attributes=[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES])
                        for oNestedUser in sorted(conn3.entries):
                            sNestedUser = str(oNestedUser.userPrincipalName).lower()
                            if sADGroupName in dADGroups.keys():
                                dADGroups[sADGroupName].append(sNestedUser)
                            else:
                                dADGroups[sADGroupName] = [sNestedUser]
        except Exception as Err:
            print("Generic problem getting properties: %s" % Err) 


    print("\nActive Directory groups:\n------------------------")
    for key, value in dADGroups.items():
        print("Found group %s with member list: %s" % (key, value))



    #########################################################################################################################
    # Read Nets file.  Make a dictionary like <groupname,[nets_list]>
    #########################################################################################################################
    print("Reading CSV mapping group names to CIDR blocks...")

    with open(net_map_file, mode='r') as infileNets:
        readerNets = csv.reader(infileNets)
        next(readerNets)
        next(readerNets)
        dNets = {AllowedGroupNameCharsReg.sub('',rows[0].replace('&','and')):",".join(rows[1:]) for rows in readerNets}
    # Check for any groups in the AD dictionary NOT in nets dictionary. 
    # Remove from new, separate nets-only version of the AD dict if not found. 
    dADGroupsWithNets = {k: dADGroups[k] for k in dNets if k in dADGroups}
    for sGrpName in dADGroups.keys():
        for sUsr in dADGroups[sGrpName]:
            if sUsr not in lADUsers:
                lADUsers.append(sUsr)
    print("\nGroups from AD to be granted network-based access:\n----------------------------------------------------------")
    for key, value in dADGroupsWithNets.items():
        print("%s, members: %s" % (key, value))



    #########################################################################################################################
    # Get a list of the io group names.  Make the list of whom to add.
    # Prevent certain admin users from being added to these unit-level groups.
    #########################################################################################################################
    lTioUsers = [] 
    print("Determining whom to add to Tenable.io groups...")
    print("\nTenable.io User Groups:\n------------------------")
    for group in tio.groups.list():
        if group["name"] in dADGroupsWithNets:
            print("ID: %s    NAME: %s" % (group["id"], group["name"] ))
            groupdetail = tio.groups.list_users(group["id"])
            for principaldetail in tio.groups.list_users(group["id"]):
                bAppend = True
                print(principaldetail["user_name"])
                if "All Users" in principaldetail["user_name"]:
                    continue
                for unmanaged_user in unmanaged_users:
                    if unmanaged_user in principaldetail["user_name"]:
                        bAppend = False
                        break
                if  (principaldetail["user_name"] not in lTioUsers) and bAppend is True: 
                    lTioUsers.append(principaldetail["user_name"])
            print("--")
    print()
    

    
    #########################################################################################################################
    # Create Tenable users if they are in AD groups but don't exist in TIO. 
    #########################################################################################################################
    print("Creating users from AD groups who do not exist in Tenable.io...")

    for sADUser in lADUsers:
        bCreate = True
        #We only need to create if there's no user in io at all.
        for dTioUser in lAllTioUsers: 
            if dTioUser["user_name"] == sADUser:
                 bCreate = False
        if sADUser not in lTioUsers and bCreate is True:
            print("Creating user: %s" % sADUser)
            print("The user: %s" % dADUserToName )
            try:
                if sADUser in dADUserToName.keys():
                    tio.users.create(sADUser,"".join(random.sample(all_chars,32)),32,\
                                     name=dADUserToName[sADUser].split(',')[1] + ' ' + dADUserToName[sADUser].split(',')[0])
                else:
                    tio.users.create(sADUser,"".join(random.sample(all_chars,32)),32)
            except Exception as E:
                print("Error creating user %s: %s" % (sADUser,E))
        
    lAllTioUsers = tio.users.list()  #Updating this, now that we have added anyone new from AD, to be complete.



    #########################################################################################################################
    # Disable all users that are in TIO but not in AD 
    #########################################################################################################################
    print("Checking if any io users need to be disabled...")
    for sTioUser in lTioUsers:
        if sTioUser not in lADUsers:
            for dTioUser in lAllTioUsers: 
                if dTioUser["user_name"] == sTioUser:
                    print("Disabling account: %s" % sTioUser)
                    tio.users.enabled(dTioUser["id"],False)  

    dTioUserUUID = {}
    for dUser in lAllTioUsers:
        dTioUserUUID[dUser["user_name"]] = dUser["uuid"]



    #########################################################################################################################
    # Add TIO USER groups that exist in AD but not io, and create agent groups for these new groups if option is selected
    #########################################################################################################################
    print("\nAdding io groups for new corresponding AD groups (and default agent groups if option specified)...")
    for sGroupName in dADGroups.keys(): 
        if sGroupName not in lTioUGNames:
            dNewUserGroup = tio.groups.create(sGroupName) #add the user group
            print("Created io User group: '%s'" % sGroupName)
            if UserGroup_With_Access_to_All_AgentGroups != None:
                iCurrentUserGroupID = dNewUserGroup['id']

                dNewAgentGroup = tio.agent_groups.create(sGroupName) 
                print("Created io agent group: '%s'" % sGroupName)
          
                iCurrentAgentGroupID = dNewAgentGroup['id']

                dACL = {"type":"default","permissions":0}
                tio.permissions.change("agent-group",iCurrentAgentGroupID,dACL)
                dACL = {"type":"group","permissions":16,"id":iCurrentUserGroupID}
                tio.permissions.change("agent-group",iCurrentAgentGroupID,dACL)
                dACL = {"type":"group","permissions":16,"id":iAdminUserGroupID}
                tio.permissions.change("agent-group",iCurrentAgentGroupID,dACL)

    # Refresh the list of io User Groups now that we have updated it.
    lUserGroups = tio.groups.list()

    # Now we also need a usergroup name to ID mapping for that we are about to do (add users to groups)
    dUserGroupNameID={}
    for dUserGroup in lUserGroups:
        dUserGroupNameID[dUserGroup["name"]] = dUserGroup["id"]

    dTioUserNameID = {}
    lTioUsersFromList = tio.users.list()
    for dUserFromList in lTioUsersFromList:
        dTioUserNameID[dUserFromList["user_name"]] = dUserFromList["id"] 
 


    #########################################################################################################################
    # Add AD users that are not in the corresponding TIO user groups 
    #########################################################################################################################
    print("\nSyncing io group membership with AD group membership...")
    for sGrpName in dUserGroupNameID.keys():
        lTioUGUserObjs = []
        lTioUGUserNames = [] 
        if sGrpName in dADGroups.keys():

            #get the io "User group" users for the matching group there
            lTioUGUserObjs = tio.groups.list_users(dUserGroupNameID[sGrpName])
            for oUser in lTioUGUserObjs:
               lTioUGUserNames.append(oUser["user_name"])

            #Get all the AD users for this group, which we must then compare to the io User group users...
            #First we will add users to the io group if they're in the AD group but not io
            for sCurrentUser in dADGroups[sGrpName]:
                if sCurrentUser not in lTioUGUserNames:
                    print("Adding user %s to io group %s..." % (sCurrentUser,sGrpName))
                    try:
                        tio.groups.add_user(dUserGroupNameID[sGrpName],dTioUserNameID[sCurrentUser]) 
                    except Exception as E:
                        print("Error adding user %s to group %s: %s" % (sCurrentUser,sGrpName,E))

            #Finally we will remove users from the io group if they're in the AD group but not the io group
            for sCurrentUser in lTioUGUserNames:
                if sCurrentUser not in dADGroups[sGrpName]:
                    print("removing user %s from io group %s..." % (sCurrentUser,sGrpName))
                    try:
                        tio.groups.delete_user(dUserGroupNameID[sGrpName],dTioUserNameID[sCurrentUser])
                    except Exception as E:
                        print("Error removing user %s from group %s: %s" % (sCurrentUser,sGrpName,E))



    #########################################################################################################################
    # Create/Edit Tags with CIDR blocks for groups with nets 
    # Grant access to tag if not already granted
    #########################################################################################################################
    print("\nCreating and Editing Tags with nets for groups...")
    dTagNameUUID = {}
    oTags = tio.tags.list(('category_name','eq','Networks'))
    for dTag in oTags:
        dTagNameUUID[dTag['value']] = dTag['uuid']

    #Check if the corresponding tag exits.  If it does not, create it.
    for sGrpName in dADGroupsWithNets.keys():
        if sGrpName != 'ITS':
            if sGrpName in dTagNameUUID.keys():
                print("Updating tag and permission for %s..." % sGrpName)
                print("%s has %s networks." % (sGrpName,len(dNets[sGrpName].split(','))))
                tio.tags.edit(dTagNameUUID[sGrpName],filters=[('ipv4', 'eq', dNets[sGrpName])])
            else:
                print("Creating new tag and permission for %s..." % sGrpName)
                print("%s has %s networks." % (sGrpName,len(dNets[sGrpName].split(','))))

                # Get usergroup to uuid mapping.  Make sure our list is up to date (we've possibly added users since start).
                for user_group in tio.groups.list():
                    if str(user_group['name']) not in dUserGroupUUID:
                        dUserGroupUUID[str(user_group['name'])] = user_group['uuid']

                oNewTag = tio.tags.create('Networks', sGrpName, filters=[('ipv4', 'eq', dNets[sGrpName])])

                #After initial creation, we need the user group of same name to have pemissions to the tag
                payload = {
                    "name": "Tag 'Networks:%s' unit permissions" % sGrpName,
                    "actions": ["CanUse","CanScan","CanView"],
                    "objects": [
                        {
                            "name": "Networks,%s" % sGrpName,
                            "type": "Tag",
                            "uuid": oNewTag['uuid'] 
                        }
                    ],
                    "subjects": [
                        {
                            "name": sGrpName,
                            "type": "UserGroup",
                            "uuid": dUserGroupUUID[sGrpName] 
                        }
                    ]
                } 
                response = requests.post("https://cloud.tenable.com/api/v3/access-control/permissions", json=payload, 
                                         headers=headers)



    #########################################################################################################################
    # Refresh Navi Database with up-to-date assets
    #########################################################################################################################
    print("\nUsing Navi to tag agents from configured groups...")
    offset = 0
    total = 0

    os.system('navi update assets')
    while offset <= total:
        querystring = {"limit": "5000", "offset": offset}
        group_data = request_data('GET', '/scanners/1/agent-groups', params=querystring)

        for agent_group in group_data['groups']:
            group_name = agent_group['name']
            print("On %s..." % group_name)
            #group_id = agent_group['id']

            #Use NAVI to tag all the assets corresponding to the agents in the group
            #Tag name will match agent group name.
            for sIAUnit in lIAUnit:
                if group_name.lower().startswith(sIAUnit.lower() + " ") or \
                   group_name.lower().startswith(sIAUnit.lower() + "-") or \
                   group_name.lower() == sIAUnit.lower():
                    print("Tagging group '%s' for unit '%s'" % (group_name, sIAUnit))
                    os.system('navi tag --c "Unit Agent Groups" --v "%s" --group "%s"' % (group_name, group_name))

                    # Give appropriate user group access to the tag
                    print("Granting tag access for agent group. Tags will not be created while an agent group still has 0 " \
                          "assets. There may be a 'duplicate' error, which can be ignored if access has previously been " \
                          "granted.")
                    os.system('navi access create --c "Unit Agent Groups" --v "%s" --uuid "%s" --usergroup "%s" --perm CanScan' % \
                              (group_name,dUserGroupUUID[sIAUnit],sIAUnit))
                    os.system('navi access create --c "Unit Agent Groups" --v "%s" --uuid "%s" --usergroup "%s" --perm CanView' % \
                              (group_name,dUserGroupUUID[sIAUnit],sIAUnit))
        offset = offset + 5000
    print("\nNavi tagging complete.")
