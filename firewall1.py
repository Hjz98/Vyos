#!/usr/bin/python

import re
import vymgmt

#<------------------------------- Firewall ----------------------------->
def createfire(ip,uname,passw,portq,rname,rule,action,rgroup):
	vyos = vymgmt.Router( ip , uname , password=passw , port=portq )
	vyos.login()
	vyos.configure()
	vyos.set("firewall name %s rule %s action %s" %(rname,rule,action))
	vyos.set("firewall name %s rule %s destination group network-group %s" %(rname,rule,rgroup))
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

def readfire(ip,uname,passw,portq):
	vyos = vymgmt.Router( ip , uname , password=passw , port=portq )
	vyos.login()
	vyos.configure()
	print (vyos.run_conf_mode_command("show firewall name"))
	x = vyos.run_conf_mode_command("show firewall name")
	vyos.exit()
	vyos.logout()
	y = re.split('\r\n',x)
	return y

def updatefire(ip,uname,passw,portq,dername,drule,rname,rule,action,rgroup):
	vyos = vymgmt.Router( ip , uname , password=passw , port=portq )
	vyos.login()
	vyos.configure()
	vyos.delete("firewall name %s rule %s" %(dername,drule))
	vyos.set("firewall name %s rule %s action %s" %(rname,rule,action))
	vyos.set("firewall name %s rule %s destination group network-group %s" %(rname,rule,rgroup))
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

def deletefire(ip,uname,passw,portq,dername):
	vyos = vymgmt.Router( ip , uname , password=passw , port=portq )
	vyos.login()
	vyos.configure()
	vyos.delete("firewall name %s" %dername)
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

#<---------------------------FIRE GROUP----------------------------------->
def createfiregroup(ip,uname,passw,portq,netname,netadmask):
	vyos = vymgmt.Router(ip,uname,password=passw,port=portq)
	vyos.login()
	vyos.configure()
	vyos.set("firewall group network-group %s network %s" %(netname,netadmask))
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

def readfiregroup(ip,uname,passw,portq):
	vyos = vymgmt.Router(ip,uname,password=passw,port=portq)
	vyos.login()
	vyos.configure()
	print(vyos.run_conf_mode_command("show firewall group"))
	x = vyos.run_conf_mode_command("show firewall group")
	y = re.split('\r\n',x)
	vyos.exit()
	vyos.logout()
	return y

def updatefiregroup(ip,uname,passw,portq,delgroup,netname,netadmask):
	vyos = vymgmt.Router(ip,uname,password=passw,port=portq)
	vyos.login()
	vyos.configure()
	vyos.delete("firewall group network-group %s" %delgroup)
	vyos.set("firewall group network-group %s network %s" %(netname,netadmask))
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

def deletefiregroup(ip,uname,passw,portq,delgroup):
	vyos = vymgmt.Router(ip,uname,password=passw,port=portq)
	vyos.login()
	vyos.configure()
	vyos.delete("firewall group network-group %s" %delgroup)
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()
