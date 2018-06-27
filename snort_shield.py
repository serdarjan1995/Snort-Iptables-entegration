#!/usr/bin/env python3
import socket
import struct
import xml.etree.ElementTree as etree
import paramiko
import calendar
import time
import pymysql
import sys
import linecache

#################################################
## Iptables running machine's ip and user info ##
hostname = '192.168.111.135'
username = 'root'
password = 'rootfirewall'
port = 22
#################################################

##########################
## Database information ##
DBSERVER = "localhost"
DBUSERNAME = "root"
DBPASS = "root"
DBNAME = "snort"
##########################

################################
### files below should be created before ###
RULE_EXPORT_XML = '/etc/snort/snortShield/rules2.xml'
RULE_IMPORTED_XML = '/etc/snort/snortShield/rules.xml'
RULE_TEST_XML = '/etc/snort/snortShield/test_rule.xml'
################################

block_expires_in_minutes = 10
clear_ip_list_time = 10
alert_threshold = 2
alert_threshold_for_port_scan = 70
alert_threshold_for_ddos = 300

def look_for_alert(iplist,ipsrc,ipdst,ipproto,s_port,d_port):
        for entry in iplist:
                if(entry[0]==ipsrc and entry[1]==ipdst and entry[2]==ipproto and entry[3]==s_port and entry[4]==d_port):
                        return entry


def is_port_scan(iplist,ipsrc,ipdst,ipproto):
        count = 0
        for entry in iplist:
                if(entry[0]==ipsrc and entry[1]==ipdst and entry[2]==ipproto):
                        count+=1
                if(count>alert_threshold_for_port_scan):
                        return 1
        return 0

def is_ddos(iplist,ipdst,ipproto,d_port):
        count = 0
        for entry in iplist:
                if(entry[1]==ipdst and entry[2]==ipproto and entry[4]==d_port):
                        count+=1
                        if(count>alert_threshold_for_ddos):
                                return 1
                else:
                        count = 1
        return 0
                
def ssh_handshake():
        handshakeDone = 0
        while(handshakeDone==0):
                try:
                        client_ssh = paramiko.SSHClient()      
                        client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client_ssh.connect(hostname,port=port, username=username, password=password)
                        client_ssh.exec_command('iptables-save > /etc/iptables/rules_test.v4')
                        client_ssh.exec_command('iptables-xml < /etc/iptables/rules_test.v4 > /etc/iptables/rules_test.xml')
                        sftp = client_ssh.open_sftp()
                        sftp.get('/etc/iptables/rules_test.xml',RULE_TEST_XML)
                        sftp.close()
                        tree = etree.parse(RULE_TEST_XML)
                        root = tree.getroot()
                        elementChainForward = root.find("./table[@name='filter']").find("chain[@name='FORWARD']")
                        handshakeDone=1
                except Exception as err: PrintException();print('Handshake unsuccessful ',repr(err))
                finally: client_ssh.close()



def ssh_import_rule():
        ## importing rules
        try:
                client_ssh = paramiko.SSHClient()      
                client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client_ssh.connect(hostname,port=port, username=username, password=password)
                #print ('\nssh connected to ', username, '@',hostname,'\n')
                client_ssh.exec_command('iptables-save > /etc/iptables/rules.v4')
                #print('iptables-save executed')
                client_ssh.exec_command('iptables-xml < /etc/iptables/rules.v4 > /etc/iptables/rules.xml')
                #print('iptables-xml executed')
                sftp = client_ssh.open_sftp()
                #print('sftp opened')
                sftp.get('/etc/iptables/rules.xml',RULE_IMPORTED_XML)
                #print('sftp: rules.xml get')
                sftp.close()
        except Exception as err: PrintException(); print('[ERROR] SSH Rule import module error ',repr(err))
        finally: client_ssh.close()
        return 1
        
def ssh_export_rule():
        ## exporting rules
        try:    
                client_ssh = paramiko.SSHClient()      
                client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client_ssh.connect(hostname,port=port, username=username, password=password)
                #print ('\n ssh connected to ', username, '@',hostname,'\n')
                sftp = client_ssh.open_sftp()
                #print('sftp opened')
                sftp.put(RULE_EXPORT_XML,'/etc/iptables/rules.xml')
                #print('sftp.put executed')
                client_ssh.exec_command('xsltproc /etc/iptables/iptables.xslt /etc/iptables/rules.xml > /etc/iptables/rules.v4')
                #print('xsltproc executed')
                client_ssh.exec_command('iptables-restore < /etc/iptables/rules.v4') #### bug
                client_ssh.exec_command('iptables-restore < /etc/iptables/rules.v4')
                #print('iptables-restore executed')
                print('\t\t\t ssh rule updated')
                sftp.close()
        except Exception as err: PrintException(); print('[ERROR] SSH Rule export module error ',repr(err))
        finally: client_ssh.close()
        return 1



def check_rules_to_remove():
        try:    
                deleted_rule_list = []
                successfull_imported_xml = 0
                retry = 4 
                while(successfull_imported_xml == 0 and retry>0):
                        try:    
                                tree = etree.parse(RULE_IMPORTED_XML)
                                root = tree.getroot()
                                elementChainForward = root.find("./table[@name='filter']")
                                elementChainForward = elementChainForward.find("chain[@name='FORWARD']")
                                successfull_imported_xml = 1
                        except:
                                PrintException()
                                ssh_import_rule()
                                retry -= 1
                if(retry>0):
                        deletedRule = 0
                        nearest_expire = block_expires_in_minutes
                        for rule in elementChainForward.findall('rule'):
                                try:
                                        if(rule.find('conditions').find('match').find('s') == None):
                                                ipsrc_in_xml = None
                                        else:
                                                ipsrc_in_xml = rule.find('conditions').find('match').find('s').text
                                                ipsrc_in_xml = ipsrc_in_xml.split('/')
                                                ipsrc_in_xml = struct.unpack("!L", socket.inet_aton(ipsrc_in_xml[0]))[0] 

                                        ipdst_in_xml = rule.find('conditions').find('match').find('d').text
                                        ipdst_in_xml = ipdst_in_xml.split('/')
                                        ipdst_in_xml = struct.unpack("!L", socket.inet_aton(ipdst_in_xml[0]))[0]
                                except Exception as err: continue; #print ("Warning! Unmatched rule condition at check_rules_to_remove(), ", repr(err)); continue;

                                ipproto_in_xml = None
                                s_port_in_xml = None
                                d_port_in_xml = None
                                hasSpeceficProto = 0
                                has_ports = 0
                                sql_success = 0
                                if(rule.find('conditions').find('match').find('p') != None):
                                        hasSpeceficProto = 1
                                        ipproto_in_xml =  rule.find('conditions').find('match').find('p').text
                                        if(ipproto_in_xml == 'tcp'):
                                                ipproto_in_xml = 6
                                                if(rule.find('conditions').find('tcp') != None):
                                                        if(rule.find('conditions').find('tcp').find('sport') != None):
                                                                s_port_in_xml = rule.find('conditions').find('tcp').find('sport').text
                                                        else:
                                                                s_port_in_xml = None
                                                        d_port_in_xml = rule.find('conditions').find('tcp').find('dport').text
                                                        has_ports=1
                                        if(ipproto_in_xml == 'icmp'):
                                                ipproto_in_xml = 1
                                        if(ipproto_in_xml == 'udp'):
                                                ipproto_in_xml = 17
                                                if(rule.find('conditions').find('udp') != None):
                                                        if(rule.find('conditions').find('udp').find('sport') != None):
                                                                s_port_in_xml = rule.find('conditions').find('udp').find('sport').text
                                                        else:
                                                                s_port_in_xml = None
                                                        d_port_in_xml = rule.find('conditions').find('udp').find('dport').text
                                                        has_ports=1
                                        if(has_ports==1):
                                                if(ipsrc_in_xml==None and s_port_in_xml==None):
                                                        sql_select = "SELECT * from blocked_ip where ipsrc is NULL and ipdst=%d and protocol=%d and s_port is NULL and d_port=%d" \
                                                                                % (ipdst_in_xml,int(ipproto_in_xml),int(d_port_in_xml))
                                                else:
                                                        sql_select = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' and s_port='%d' and d_port='%d'" \
                                                                                % (ipsrc_in_xml,ipdst_in_xml,int(ipproto_in_xml),int(s_port_in_xml),int(d_port_in_xml))
                                        else:
                                                sql_select = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' and s_port is NULL and d_port is NULL " \
                                                                                % (ipsrc_in_xml,ipdst_in_xml,int(ipproto_in_xml))
                                else:
                                        sql_select = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol is NULL" \
                                                                        % (ipsrc_in_xml,ipdst_in_xml)
                                try:
                                        sql_success = cursor.execute(sql_select)
                                        if(sql_success>0):
                                                record = cursor.fetchone()
                                                blocked_time = record[3]
                                                delete_after = record[4]
                                                rule_time_epoch = int(blocked_time.strftime('%s'))
                                                current_time_epoch = time.mktime(time.localtime())
                                                minutes_left = delete_after - (current_time_epoch-rule_time_epoch)/60
                                                print('\n Rule created: %s, now: %s , minutes left %d min' % \
                                                      (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rule_time_epoch)), \
                                                       time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time_epoch)),minutes_left))
                                                if (minutes_left<=0):
                                                        elementChainForward.remove(rule)
                                                        deletedRule += 1
                                                        if(hasSpeceficProto == 1 and has_ports==1):
                                                                deleted_rule_list.append([record[0],record[1],record[2],record[3].strftime('%Y-%m-%d %H:%M:%S'),record[5],record[6]])
                                                        elif(hasSpeceficProto == 1):
                                                                deleted_rule_list.append([record[0],record[1],record[2],record[3].strftime('%Y-%m-%d %H:%M:%S'),None,None])
                                                        else:
                                                                deleted_rule_list.append([record[0],record[1],None,record[3].strftime('%Y-%m-%d %H:%M:%S'),None,None])
                                                        print('\taction:delete')
                                                if(minutes_left<nearest_expire):
                                                        nearest_expire = minutes_left
                                except Exception as err:
                                        PrintException()
                                        print ("Error:  At check_rules_to_remove() in section 'remove rule', ", repr(err));

                        if(deletedRule > 0):
                                print('\taction: export')
                                tree.write(RULE_EXPORT_XML)
                                return -1, deleted_rule_list
                        print('nearest expire after: ', nearest_expire)
                        return nearest_expire, deleted_rule_list
        except Exception as err: PrintException();print('[ERROR] XML rule check to remove module error ' + repr(err))

                
                
def delete_rules_from_table(deleted_rule_list):
        for record in deleted_rule_list:
                if(record[2] == None):
                        sql_delete = "DELETE FROM blocked_ip where ipsrc='%d' and ipdst='%d' and protocol is NULL and blocked_time='%s'" \
                                        % (record[0],record[1],record[3])
                        sql_insert = "INSERT INTO deleted_rule(ipsrc,ipdst,protocol,blocked_time,unblocked_time,s_port,d_port) VALUES (%d,%d,NULL,'%s','%s',NULL,NULL)" \
                                % (record[0],record[1],record[3],time.strftime('%Y-%m-%d %H:%M:%S'))
                elif(record[4] == None and record[5] == None):
                        sql_delete = "DELETE FROM blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' and blocked_time='%s' and s_port is NULL and d_port is NULL" \
                                        % (record[0],record[1],record[2],record[3])
                        sql_insert = "INSERT INTO deleted_rule(ipsrc,ipdst,protocol,blocked_time,unblocked_time,s_port,d_port) VALUES (%d,%d,%d,'%s','%s',NULL,NULL)" \
                                % (record[0],record[1],record[2],record[3],time.strftime('%Y-%m-%d %H:%M:%S'))
                elif(record[0] == None and record[4] == None):
                        sql_delete = "DELETE FROM blocked_ip where ipsrc is NULL and ipdst=%d and protocol=%d and blocked_time='%s' and s_port is NULL and d_port=%d" \
                                        % (record[1],record[2],record[3],record[5])
                        sql_insert = "INSERT INTO deleted_rule(ipsrc,ipdst,protocol,blocked_time,unblocked_time,s_port,d_port) VALUES (NULL,%d,%d,'%s','%s',NULL,%d)" \
                                % (record[1],record[2],record[3],time.strftime('%Y-%m-%d %H:%M:%S'),record[5])
                else:
                        sql_delete = "DELETE FROM blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' and blocked_time='%s' and s_port='%d' and d_port=%d" \
                                        % (record[0],record[1],record[2],record[3],record[4],record[5])
                        sql_insert = "INSERT INTO deleted_rule(ipsrc,ipdst,protocol,blocked_time,unblocked_time,s_port,d_port) VALUES (%d,%d,%d,'%s','%s',%d,%d)" \
                                % (record[0],record[1],record[2],record[3],time.strftime('%Y-%m-%d %H:%M:%S'),record[4],record[5])
                
                try: cursor.execute(sql_delete); db.commit();
                except Exception as err: db.rollback(); PrintException();print ("[Error]: unable to delete data from blocked_ip table, ",repr(err))
                

                try: cursor.execute(sql_insert); db.commit();
                except Exception as err: db.rollback(); PrintException();print ("[Error]: unable to write data to deleted_rule table, ",repr(err))

                        
def iptablesRuleViaSSH(ip_src,ip_dst,ip_proto,s_port,d_port):
        success = 0
        str_exec = ''
        try:
                client_ssh = paramiko.SSHClient()      
                client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client_ssh.connect(hostname,port=port, username=username, password=password)
                if(ip_proto!=None):
                        if((ip_proto==6 or ip_proto==17) and s_port!=None and d_port!=None):
                                str_exec = 'iptables -A FORWARD -s '+str(ip_src)+' -d '+str(ip_dst)+\
                                                        ' -p '+str(ip_proto)+' --sport '+str(s_port)+' --dport '+str(d_port)+' -j DROP'
                        elif((ip_proto==6 or ip_proto==17) and ip_src == None and s_port==None):
                                str_exec = 'iptables -A FORWARD -d '+str(ip_dst)+' -p '+str(ip_proto)+' --dport '+str(d_port)+' -j DROP'
                        else:
                                str_exec = 'iptables -A FORWARD -s '+str(ip_src)+' -d '+str(ip_dst)+' -p '+str(ip_proto)+' -j DROP'
                else:
                        str_exec = 'iptables -A FORWARD -s '+str(ip_src)+' -d '+str(ip_dst)+' -j DROP'
                print(str_exec)
                client_ssh.exec_command(str_exec)
                success=1
        except Exception as err: PrintException();print('[ERROR] iptablesRuleViaSSH error ',repr(err))
        finally: client_ssh.close()
        return success

def isRuleInXML(ipsrc,ipdst,ipproto,s_port,d_port):
        try:    
                found = 0
                successfull_imported_xml = 0
                retry = 4 
                while(successfull_imported_xml == 0 and retry>0):
                        try:    
                                tree = etree.parse(RULE_IMPORTED_XML)
                                root = tree.getroot()
                                elementChainForward = root.find("./table[@name='filter']")
                                elementChainForward = elementChainForward.find("chain[@name='FORWARD']")
                                successfull_imported_xml = 1
                        except:
                                PrintException()
                                ssh_import_rule()
                                retry -= 1
                if(retry>0):
                        if(ipsrc==None and s_port==None):
                                for rule in elementChainForward.findall('rule'):
                                        try:
                                                ipdst_in_xml = rule.find('conditions').find('match').find('d').text
                                                ipdst_in_xml = ipdst_in_xml.split('/')
                                                ipdst_in_xml = struct.unpack("!L", socket.inet_aton(ipdst_in_xml[0]))[0]

                                                ipproto_in_xml = None
                                                d_port_in_xml = None
                                                if(rule.find('conditions').find('match').find('p') != None):
                                                        ipproto_in_xml =  rule.find('conditions').find('match').find('p').text
                                                        if(ipproto_in_xml == 'tcp'):
                                                                ipproto_in_xml = 6
                                                                if(rule.find('conditions').find('tcp') != None):
                                                                        d_port_in_xml = rule.find('conditions').find('tcp').find('dport').text
                                                        if(ipproto_in_xml == 'udp'):
                                                                ipproto_in_xml = 17
                                                                if(rule.find('conditions').find('udp') != None):
                                                                        d_port_in_xml = rule.find('conditions').find('udp').find('dport').text
                                                if(str(ipdst)==str(ipdst_in_xml) and str(ipproto)==str(ipproto_in_xml) and str(d_port)==str(d_port_in_xml) ):
                                                        found=1
                                        except Exception as err: continue;#print('Warning! Unmatched rule condition at isRuleInXML(), ',repr(err)); continue;
                                return found
                        else:
                                for rule in elementChainForward.findall('rule'):
                                        try:
                                                ipsrc_in_xml = rule.find('conditions').find('match').find('s').text
                                                ipsrc_in_xml = ipsrc_in_xml.split('/')
                                                ipsrc_in_xml = struct.unpack("!L", socket.inet_aton(ipsrc_in_xml[0]))[0] 

                                                ipdst_in_xml = rule.find('conditions').find('match').find('d').text
                                                ipdst_in_xml = ipdst_in_xml.split('/')
                                                ipdst_in_xml = struct.unpack("!L", socket.inet_aton(ipdst_in_xml[0]))[0]

                                                ipproto_in_xml = None
                                                s_port_in_xml = None
                                                d_port_in_xml = None
                                                has_ports = 0
                                                if(rule.find('conditions').find('match').find('p') != None):
                                                        ipproto_in_xml =  rule.find('conditions').find('match').find('p').text
                                                        if(ipproto_in_xml == 'tcp'):
                                                                ipproto_in_xml = 6
                                                                if(rule.find('conditions').find('tcp') != None):
                                                                        s_port_in_xml = rule.find('conditions').find('tcp').find('sport').text
                                                                        d_port_in_xml = rule.find('conditions').find('tcp').find('dport').text
                                                                        has_ports=1
                                                        if(ipproto_in_xml == 'icmp'):
                                                                ipproto_in_xml = 1
                                                        if(ipproto_in_xml == 'udp'):
                                                                ipproto_in_xml = 17
                                                                if(rule.find('conditions').find('udp') != None):
                                                                        s_port_in_xml = rule.find('conditions').find('udp').find('sport').text
                                                                        d_port_in_xml = rule.find('conditions').find('udp').find('dport').text
                                                                        has_ports=1
                                                if((ipproto==None and ipproto_in_xml==None) or (ipproto==1 and ipproto_in_xml==1)):
                                                        if(str(ipsrc)==str(ipsrc_in_xml) and str(ipdst)==str(ipdst_in_xml)):
                                                                found=1
                                                elif(has_ports==1):
                                                        if(str(ipsrc)==str(ipsrc_in_xml) and str(ipdst)==str(ipdst_in_xml) and str(ipproto)==str(ipproto_in_xml) and \
                                                                str(s_port)==str(s_port_in_xml) and str(d_port)==str(d_port_in_xml) ):
                                                                found=1
                                                else:
                                                        if(str(ipsrc)==str(ipsrc_in_xml) and str(ipdst)==str(ipdst_in_xml) and str(ipproto)==str(ipproto_in_xml) and \
                                                                s_port==None and d_port==None ):
                                                                found=1
                                        except Exception as err: continue;#print('Warning! Unmatched rule condition at isRuleInXML(), ',repr(err)); continue;
                                return found
        except Exception as err: PrintException(); print('Error: isRuleInXML() ',repr(err)); return None
                
def checkRuleInDatabase():
        # check rules that does not exist in firewall but is in database
        sql_select = "SELECT * from blocked_ip"
        ssh_import_rule()
        try:
                cursor.execute(sql_select)
                results = cursor.fetchall()
                for row in results:
                        ipsrc = row[0]
                        ipdst = row[1]
                        ipproto = row[2]
                        s_port = row[5]
                        d_port = row[6]
                        result = isRuleInXML(ipsrc,ipdst,ipproto,s_port,d_port)
                        if(result == 0):
                                iptablesRuleViaSSH(ipsrc,ipdst,ipproto,s_port,d_port)
                                print ("Warning:  Existing rule in database was not found in Firewall's list, insert it..., ");
        except Exception as err: print('Error: checkRuleInDatabase() ',repr(err))
        
        # check rules that does not exist in database but is in firewall
        ssh_import_rule()
        successfull_imported_xml = 0
        retry = 4 
        while(successfull_imported_xml == 0 and retry>0):
                try:    
                        tree = etree.parse(RULE_IMPORTED_XML)
                        root = tree.getroot()
                        elementChainForward = root.find("./table[@name='filter']")
                        elementChainForward = elementChainForward.find("chain[@name='FORWARD']")
                        successfull_imported_xml = 1
                except:
                        PrintException()
                        ssh_import_rule()
                        retry -= 1
        if(retry>0):
                try:    
                        tree = etree.parse(RULE_IMPORTED_XML)
                        root = tree.getroot()
                        elementChainForward = root.find("./table[@name='filter']").find("chain[@name='FORWARD']")
                        for rule in elementChainForward.findall('rule'):
                                s_port_in_xml = None
                                d_port_in_xml = None
                                try:
                                        if(rule.find('conditions').find('match').find('s') == None):
                                                ipsrc_in_xml = None
                                        else:
                                                ipsrc_in_xml = rule.find('conditions').find('match').find('s').text
                                                ipsrc_in_xml = ipsrc_in_xml.split('/')
                                                ipsrc_in_xml = struct.unpack("!L", socket.inet_aton(ipsrc_in_xml[0]))[0] 

                                        ipdst_in_xml = rule.find('conditions').find('match').find('d').text
                                        ipdst_in_xml = ipdst_in_xml.split('/')
                                        ipdst_in_xml = struct.unpack("!L", socket.inet_aton(ipdst_in_xml[0]))[0]
                                except Exception as err: continue;#print ("Warning! Unmatched rule condition at check_rules_to_remove(), ", repr(err)); continue;

                                hasSpeceficProto = 0
                                has_ports = 0
                                if(rule.find('conditions').find('match').find('p') != None):
                                        ipproto_in_xml =  rule.find('conditions').find('match').find('p').text
                                        if(ipproto_in_xml == 'tcp'):
                                                ipproto_in_xml = 6
                                                if(rule.find('conditions').find('tcp') != None):
                                                        if(rule.find('conditions').find('tcp').find('sport') != None):
                                                                s_port_in_xml = rule.find('conditions').find('tcp').find('sport').text
                                                        else:
                                                                s_port_in_xml = None
                                                        d_port_in_xml = rule.find('conditions').find('tcp').find('dport').text
                                                        has_ports=1
                                        if(ipproto_in_xml == 'icmp'):
                                                ipproto_in_xml = 1
                                        if(ipproto_in_xml == 'udp'):
                                                ipproto_in_xml = 17
                                                if(rule.find('conditions').find('udp') != None):
                                                        if(rule.find('conditions').find('udp').find('sport') != None):
                                                                s_port_in_xml = rule.find('conditions').find('udp').find('sport').text
                                                        else:
                                                                s_port_in_xml = None
                                                        d_port_in_xml = rule.find('conditions').find('udp').find('dport').text
                                                        has_ports=1
                                        if(has_ports==1):
                                                if(ipsrc_in_xml==None and s_port_in_xml==None):
                                                        sql_select = "SELECT * from blocked_ip where ipsrc is NULL and ipdst=%d and protocol=%d and s_port is NULL and d_port='%d' " \
                                                                                % (ipdst_in_xml,int(ipproto_in_xml),int(d_port_in_xml))
                                                else:
                                                        sql_select = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' and s_port='%d' and d_port='%d' " \
                                                                                % (ipsrc_in_xml,ipdst_in_xml,int(ipproto_in_xml),int(s_port_in_xml),int(d_port_in_xml))
                                        else:
                                                sql_select = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d'" \
                                                                                % (ipsrc_in_xml,ipdst_in_xml,int(ipproto_in_xml))
                                        hasSpeceficProto = 1
                                else:
                                        sql_select = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d'" \
                                                                        % (ipsrc_in_xml,ipdst_in_xml)
                                try:
                                        sql_success = cursor.execute(sql_select)
                                        if(sql_success==0):
                                                print ("Warning:  Existing Firewall rule was not found in database, insert it..., ");
                                                if(hasSpeceficProto==1 and has_ports==1):
                                                        if(ipsrc_in_xml==None and s_port_in_xml==None):
                                                                sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after,s_port,d_port) VALUES (NULL,%s,%s,'%s',%s,NULL,%d)" \
                                                                % (str(ipdst_in_xml),str(ipproto_in_xml),time.strftime('%Y-%m-%d %H:%M:%S'),block_expires_in_minutes,int(d_port_in_xml))
                                                        else:
                                                                sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after,s_port,d_port) VALUES (%s,%s,%s,'%s',%s,%d,%d)" \
                                                                % (str(ipsrc_in_xml),str(ipdst_in_xml),str(ipproto_in_xml),time.strftime('%Y-%m-%d %H:%M:%S'),block_expires_in_minutes,int(s_port_in_xml),int(d_port_in_xml))
                                                elif(hasSpeceficProto==1):
                                                        sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after) VALUES (%s,%s,%s,'%s',%d)" \
                                                        % (str(ipsrc_in_xml),str(ipdst_in_xml),str(ipproto_in_xml),time.strftime('%Y-%m-%d %H:%M:%S'),block_expires_in_minutes)
                                                else:
                                                        sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after) VALUES (%s,%s,NULL,'%s',%d)" \
                                                        % (str(ipsrc_in_xml),str(ipdst_in_xml),time.strftime('%Y-%m-%d %H:%M:%S'),block_expires_in_minutes)
                                                try: cursor.execute(sql_insert); db.commit();
                                                except Exception as erro: db.rollback(); print ("Error: unable to write data to blocked_ip table (rule_check), ",repr(err))
                                except Exception as err2:
                                        print ("Error:  At checkRuleInDatabase(), ", repr(err2));
                except Exception as err: PrintException(); print('Error: no rules in xml ',repr(err))

def main():
        last_cid = 0
        correlation_list = []
        wait_to_remove = 0
        success = 0
        prev_cid = 0
        correlation_clear_time = time.time()+block_expires_in_minutes*60

        ssh_handshake()
        ############### LOOP
        while(1):
                if(time.time() > correlation_clear_time):
                        correlation_list = []
                        correlation_clear_time = time.time()+clear_ip_list_time*60
                prev_cid = last_cid
                sql = "SELECT * from processed_events order by cid desc limit 1"
                try:
                        cursor.execute(sql)
                        current_cid = cursor.fetchone()[0]
                        if(last_cid == current_cid):
                                checkRuleInDatabase()
                                if( wait_to_remove <= calendar.timegm(time.localtime()) ):
                                        success = ssh_import_rule()
                                        if( success == 1):
                                                doExport, deleted_rule_list = check_rules_to_remove()
                                                if (doExport == -1):
                                                        success = ssh_export_rule()
                                                        if(success == 1): delete_rules_from_table(deleted_rule_list)
                                                        checkRuleInDatabase()

                                                else: wait_to_remove = calendar.timegm(time.localtime()) + doExport*60
                        else:
                                last_cid = current_cid
                        if(last_cid is None): last_cid = 0;
                except Exception as err:
                        print ("Error: unable to fetch data from proccessed_events table ,",repr(err)); PrintException()


                if(prev_cid != last_cid):
                        print ("\n\n[INFO] Starting checking from last_cid=", last_cid)
                sql = "SELECT * from iphdr where cid>'%d' limit 300" % last_cid
                try:
                        cursor.execute(sql)
                        results = cursor.fetchall()
                        for row in results:
                                retry = 10
                                while( retry > 0 ):
                                        success = 0
                                        sid = row[0]
                                        cid = row[1]
                                        ip_src = row[2] #socket.inet_ntoa(struct.pack('!L', row[2]))
                                        ip_dst = row[3] #socket.inet_ntoa(struct.pack('!L', row[3]))
                                        ip_proto = row[12]
                                        s_port = None
                                        d_port = None
                                        if(ip_proto==6):
                                                sql_tcp_select = "SELECT * from tcphdr where cid='%d'" % cid
                                                cursor.execute(sql_tcp_select)
                                                row_tcp = cursor.fetchone()
                                                s_port = row_tcp[2]
                                                d_port = row_tcp[3]
                                        elif(ip_proto==17):
                                                sql_udp_select = "SELECT * from udphdr where cid='%d'" % cid
                                                cursor.execute(sql_udp_select)
                                                row_udp = cursor.fetchone()
                                                s_port = row_udp[2]
                                                d_port = row_udp[3]
                                        alert_in_list = look_for_alert(correlation_list,ip_src,ip_dst,ip_proto,s_port,d_port)
                                        if(alert_in_list is None):
                                                correlation_list.append([ip_src,ip_dst,ip_proto,s_port,d_port,1])
                                                success=1
                                        else:
                                                indx = correlation_list.index(alert_in_list)
                                                correlation_list[indx][5] += 1
                                                isDdos = is_ddos(correlation_list,ip_dst,ip_proto,d_port)
                                                if(isDdos == 1):
                                                        sql = "SELECT * from blocked_ip where ipsrc is NULL and ipdst=%d and protocol=%d and d_port=%d" \
                                                                % (correlation_list[indx][1],correlation_list[indx][2],correlation_list[indx][4])
                                                        try:
                                                                isBlocked = cursor.execute(sql)
                                                                if(isBlocked == 0):
                                                                        ip_dst = socket.inet_ntoa(struct.pack('!L', ip_dst))
                                                                        try: success = iptablesRuleViaSSH(None,ip_dst,ip_proto,None,d_port)
                                                                        except Exception as err: print (repr(err)); break;
                                                                        if( success == 1 ):
                                                                                sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after,s_port,d_port) VALUES (NULL,%d,%d,'%s',%d,NULL,%d)" \
                                                                                % (correlation_list[indx][1],correlation_list[indx][2],time.strftime('%Y-%m-%d %H:%M:%S'),block_expires_in_minutes,correlation_list[indx][4])
                                                                                try: cursor.execute(sql_insert); db.commit();
                                                                                except Exception as err: db.rollback(); print ("[Error]: unable to write data to blocked_ip table, ",repr(err))
                                                                        else: print('rule not exported')
                                                                else: success =1
                                                        except: print ("Error: unable to fetch data blocked_ip"); break;
                                                isPortScan = is_port_scan(correlation_list,ip_src,ip_dst,ip_proto)
                                                if(isPortScan==1):
                                                        sql = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d'" \
                                                                % (correlation_list[indx][0],correlation_list[indx][1],correlation_list[indx][2])
                                                        try:
                                                                isBlocked = cursor.execute(sql)
                                                                if(isBlocked == 0):
                                                                        ip_src = socket.inet_ntoa(struct.pack('!L', ip_src))
                                                                        ip_dst = socket.inet_ntoa(struct.pack('!L', ip_dst))
                                                                        try: success = iptablesRuleViaSSH(ip_src,ip_dst,ip_proto,s_port,d_port)
                                                                        except Exception as err: print (repr(err)); break;
                                                                        if( success == 1 ):
                                                                                sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after,s_port,d_port) VALUES (%d,%d,%d,'%s',%d,NULL,NULL)" \
                                                                                % (correlation_list[indx][0],correlation_list[indx][1],correlation_list[indx][2],time.strftime('%Y-%m-%d %H:%M:%S'),block_expires_in_minutes)
                                                                                try: cursor.execute(sql_insert); db.commit();
                                                                                except Exception as err: db.rollback(); print ("[Error]: unable to write data to blocked_ip table, ",repr(err))
                                                                        else: print('rule not exported')
                                                                else: success =1
                                                        except: print ("Error: unable to fetch data blocked_ip"); break;
                                                elif( correlation_list[indx][5] >= alert_threshold ):
                                                        if(ip_proto==1):
                                                                sql = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' " \
                                                                % (correlation_list[indx][0],correlation_list[indx][1],correlation_list[indx][2])
                                                        elif(ip_proto==6 or ip_proto==17):
                                                                sql = "SELECT * from blocked_ip where ipsrc='%d' and ipdst='%d' and protocol='%d' and s_port='%d' and d_port='%d' " \
                                                                % (correlation_list[indx][0],correlation_list[indx][1],correlation_list[indx][2],correlation_list[indx][3],correlation_list[indx][4])
                                                        try:
                                                                isBlocked = cursor.execute(sql)
                                                                if(isBlocked == 0):
                                                                        print(ip_src,ip_dst)
                                                                        ip_src = socket.inet_ntoa(struct.pack('!L', ip_src))
                                                                        ip_dst = socket.inet_ntoa(struct.pack('!L', ip_dst))
                                                                        try: success = iptablesRuleViaSSH(ip_src,ip_dst,ip_proto,s_port,d_port)
                                                                        except Exception as err: print (repr(err)); break;
                                                                        if( success == 1):
                                                                                if(ip_proto==1):
                                                                                        sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after) VALUES (%d,%d,%d,'%s',%d)" \
                                                                                                % (correlation_list[indx][0],correlation_list[indx][1],correlation_list[indx][2],time.strftime('%Y-%m-%d %H:%M:%S'),\
                                                                                                block_expires_in_minutes)
                                                                                elif(ip_proto==6 or ip_proto==17):
                                                                                        sql_insert = "INSERT INTO blocked_ip(ipsrc,ipdst,protocol,blocked_time,delete_after,s_port,d_port) VALUES (%d,%d,%d,'%s',%d,%d,%d)" \
                                                                                                % (correlation_list[indx][0],correlation_list[indx][1],correlation_list[indx][2],time.strftime('%Y-%m-%d %H:%M:%S'),\
                                                                                                block_expires_in_minutes,correlation_list[indx][3],correlation_list[indx][4])
                                                                                try: cursor.execute(sql_insert); db.commit();
                                                                                except Exception as err: db.rollback();PrintException(); print ("[Error]: unable to write data to blocked_ip table, ",repr(err))
                                                                        else: print('rule not exported')
                                                                else: success =1
                                                        except: PrintException();print ("Error: unable to fetch data blocked_ip");break;
                                                else: success=1
                                        if ( success == 1 ): retry = 0
                                        else:print ('Cannot process rule to Firewall. Retrying to export rule'); retry -= 1
                                if(retry <= 0 and success == 0): break;
                                if(success == 1):
                                        sql_insert = "INSERT INTO processed_events(cid) VALUES (%d)" % cid
                                        try: cursor.execute(sql_insert); db.commit();
                                        except: db.rollback(); print ("[Error]: unable to write data to processed_events table")

                except Exception as err: PrintException();print ("Error: unable to check data last_cid ", repr(err)); break
                db.commit()
                #inp = input('continue: ')
                #if(inp == 'q'):
                #        break
        print ("\nTerminated\n")
        # disconnect from db
        db.close()
        exit()

        
        
def PrintException():
        exc_type, exc_obj, tb = sys.exc_info()
        f = tb.tb_frame
        lineno = tb.tb_lineno
        filename = f.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, f.f_globals)
        print('EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj))

print("Snort Shield by Sardor")        
while(1):
        try:
                db = pymysql.connect(DBSERVER,DBUSERNAME,DBPASS,DBNAME)
                cursor = db.cursor()
                main()
        except Exception as err:
                print(repr(err))
                time.sleep(10)
        