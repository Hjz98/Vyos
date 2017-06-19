#!/usr/bin/python

from flask import Flask, jsonify
from flask import abort, make_response
from flask import request
from flask.ext.httpauth import HTTPBasicAuth
import json
import vymgmt
import staticroutes
import firewall1
import user

app = Flask(__name__)

auth = HTTPBasicAuth()

tasks = [
	{

	}
]

@auth.get_password
def get_password(username):
	if username =='jz':
		return 'password'
	return None

@auth.error_handler
def unauthorized():
	return make_response(jsonify({'error': 'Unauthorized access'}), 401)

#<---------------------------------Static Routes--------------------------->
@app.route('/staticread', methods=['POST'])
@auth.login_required
def readstatics():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq']
	}
	return jsonify({'ip routes ': staticroutes.readstatic(function['ip'],function['uname'],function['passw'],function['portq'])}) , 201

@app.route('/staticcreate', methods=['POST'])
@auth.login_required
def createstatics():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'staticnet' : request.json['staticnet'],
		'nexthop' : request.json['nexthop']
	}
	tasks.append(function)
	staticroutes.createstatic(function['ip'],function['uname'],function['passw'],function['portq'],function['staticnet'],function['nexthop'])
	return jsonify({'ip routes ': staticroutes.readstatic(function['ip'],function['uname'],function['passw'],function['portq'])}), 201

@app.route('/staticupdate', methods=['POST'] )
@auth.login_required
def updatestatics():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'delstatmask' : request.json['delstatmask'],
		'staticnet' : request.json['staticnet'],
		'nexthop' : request.json['nexthop']
	}
	tasks.append(function)
	staticroutes.updatestatic(function['ip'],function['uname'],function['passw'],function['portq'],function['delstatmask'],function['staticnet'],function['nexthop'])
	return jsonify ({'ip routes ' : staticroutes.readstatic(function['ip'],function['uname'],function['passw'],function['portq'])})

@app.route('/staticdelete', methods=['POST'] )
@auth.login_required
def deletestatics():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'delstatmask' : request.json['delstatmask']
	}
	tasks.append(function)
	staticroutes.deletestatic(function['ip'],function['uname'],function['passw'],function['portq'],function['delstatmask'])
	return jsonify ({'ip routes ': staticroutes.readstatic(function['ip'],function['uname'],function['passw'],function['portq'])}) , 201

#<--------------------------------FIREWALL-------------------------------->
@app.route('/firecreate', methods=['POST'])
@auth.login_required
def createfirerule():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'rname' : request.json['rname'],
		'rule' : request.json['rule'],
		'action' : request.json['action'],
		'rgroup' : request.json['rgroup']
	}
	tasks.append(function)
	firewall1.createfire(function['ip'],function['uname'],function['passw'],function['portq'],function['rname'],function['rule'],function['action'],function['rgroup'])
	return jsonify({'Firewall' : firewall1.readfire(function['ip'],function['uname'],function['passw'],function['portq'])}) , 201

@app.route('/fireread', methods=['POST'])
@auth.login_required
def readfirerule():
	function = {
		'ip': request.json['ip'],
		'uname': request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq']
	}
	return jsonify({'Firewall' : firewall1.readfire(function['ip'],function['uname'],function['passw'],function['portq'])}), 201

@app.route('/fireupdate', methods=['POST'])
@auth.login_required
def updatefirerule():
	function = {
		'ip': request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'dername' : request.json['dername'],
		'drule' : request.json['drule'],
		'rname' : request.json['rname'],
		'rule' : request.json['rule'],
		'action' : request.json['action'],
		'rgroup' : request.json['rgroup']
	}
	tasks.append(function)
	firewall1.updatefire(function['ip'],function['uname'],function['passw'],function['portq'],function['dername'],function['drule'],function['rname'],function['rule'],function['action'],function['rgroup'])
	return jsonify({'Firewall' : firewall1.readfire(function['ip'],function['uname'],function['passw'],function['portq'])}), 201

@app.route('/firedelete', methods=['POST'])
@auth.login_required
def deletefirerule():
	function = {
		'ip': request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'dername' : request.json['dername'],
	}
	tasks.append(function)
	firewall1.deletefire(function['ip'],function['uname'],function['passw'],function['portq'],function['dername'])
	return jsonify({'Firewall' : firewall1.readfire(function['ip'],function['uname'],function['passw'],function['portq'])}), 201

#<-------------------------------Firewall Group---------------------------->

@app.route('/groupcreate', methods=['POST'])
@auth.login_required
def groupcreate():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'netname' : request.json['netname'],
		'netadmask' : request.json['netadmask']
	}
	tasks.append(function)
	firewall1.createfiregroup(function['ip'],function['uname'],function['passw'],function['portq'],function['netname'],function['netadmask'])
	return jsonify({'Firewall groups':firewall1.readfiregroup(function['ip'],function['uname'],function['passw'],function['portq'])}) , 201

@app.route('/groupread', methods=['POST'])
@auth.login_required
def groupread():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq']
	}
	tasks.append(function)
	return jsonify ({'Firewall groups' : firewall1.readfiregroup(function['ip'],function['uname'],function['passw'],function['portq'])}), 201

@app.route('/groupupdate', methods=['POST'])
@auth.login_required
def groupupdate():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'delgroup' : request.json['delgroup'],
		'netname' : request.json['netname'],
		'netadmask' : request.json['netadmask']
	}
	tasks.append(function)
	firewall1.updatefiregroup(function['ip'],function['uname'],function['passw'],function['portq'],function['delgroup'],function['netname'],function['netadmask'])
	return jsonify({'Firewall Groups' : firewall1.readfiregroup(function['ip'],function['uname'],function['passw'],function['portq'])}) , 201

@app.route('/groupdelete' , methods=['POST'])
@auth.login_required
def groupdelete():
	function = {
		'ip' : request.json['ip'],
		'uname' : request.json['uname'],
		'passw' : request.json['passw'],
		'portq' : request.json['portq'],
		'delgroup' : request.json['delgroup']
	}
	tasks.append(function)
	firewall1.deletefiregroup(function['ip'],function['uname'],function['passw'],function['portq'],function['delgroup'])
	return jsonify({'Firewall groups' : firewall1.readfiregroup(function['ip'],function['uname'],function['passw'],function['portq'])}) , 201

#<------------------------------------USER--------------------------------->
@app.route('/usercreate', methods=['POST'])
@auth.login_required
def createuser():
	function = {
		'name' : request.json['name'],
		'fname' : request.json['fname'],
		'upass' : request.json['upass'],
		'ulevel' : request.json['ulevel']
	}
	tasks.append(function)
	user.createuser(function['name'],function['fname'],function['upass'],function['ulevel'])
	return jsonify({'Users' : user.readuser()})

@app.route('/userread', methods=['GET'])
@auth.login_required
def readuser():
	return jsonify({'Users': user.readuser()})

@app.route('/userupdate', methods=['POST'])
@auth.login_required
def updateuser():
	function = {
	'username' : request.json['username'],
	'name' : request.json['name'],
	'fname' : request.json['fname'],
	'upass' : request.json['upass'],
	'ulevel' : request.json['ulevel']
	}
	tasks.append(function)
	user.updateuser(function['username'],function['name'],function['fname'],function['upass'],function['ulevel'])
	return jsonify({'Users':user.readuser()})

@app.route('/userdel', methods=['POST'])
@auth.login_required
def deleteuser():
	function = {
		'deluser' : request.json['deluser']
	}
	tasks.append(function)
	user.deleteuser(function['deluser'])
	return jsonify({'Users' : user.readuser()})


if __name__ == '__main__':
	app.run(debug=True)
