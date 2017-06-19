#!/usr/bin/python

import vymgmt
import getpass


def createstatic(ip,uname,passw,portq,staticnet,nexthop):
	vyos = vymgmt.Router( ip , uname , password=passw, port=portq)
	vyos.login()
	vyos.configure()
	vyos.set("protocols static route %s next-hop %s" %(staticnet,nexthop))
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

def readstatic(ip,uname,passw,portq):
	vyos = vymgmt.Router(ip, uname, password=passw, port=portq)
	vyos.login()
	print(vyos.run_op_mode_command("show ip route"))
	x = vyos.run_op_mode_command("show ip route")
	y = re.split('\r\n',x)
	vyos.logout()
	return y

def updatestatic(ip,uname,passw,portq,delstatmask,staticnet,nexthop):
	vyos = vymgmt.Router(ip,uname, password=passw, port=portq)
	vyos.login()
	vyos.configure()
	vyos.delete("protocols static route %s " %delstatmask)
	vyos.set("protocols static route %s next-hop %s" %(staticnet,nexthop))
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

def deletestatic(ip,uname,passw,portq,delstatmask):
	vyos = vymgmt.Router( ip, uname, password=passw, port=portq)
	vyos.login()
	vyos.configure()
	vyos.delete("protocols static route %s " %delstatmask)
	vyos.commit()
	vyos.save()
	vyos.exit()
	vyos.logout()

