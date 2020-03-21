from pyshark import LiveCapture
import sqlite3, time

def DNSdb(data,cursor,db):
    cursor.execute("insert into DNS (IP, Type, queryName) values (?,?,?)",data)
    db.commit()

def HTTPdb(data,cursor,db):
    if len(data)==5:    sql="insert into HTTP (fullURL, IP_Source, requestType, userAgent, data) values (?,?,?,?,?)"
    elif len(data)==4:  sql="insert into HTTP (fullURL, IP_Source, requestType, userAgent) values (?,?,?,?)"
    elif len(data)==2:  sql="insert into HTTP (requestType, data) values (?,?)"
    cursor.execute(sql,data)
    db.commit()

def getHTTPinfo(packet,cursor,db,data=None):
    print("Protocol",packet.http._ws_expert_message,"from",packet.http.request_full_uri)
    print("To",packet.ip.src,"using",packet.http.user_agent)
    if data!=None:  dataToSave=[packet.http.request_full_uri, packet.ip.src, packet.http._ws_expert_message, packet.http.user_agent, data]
    else:   dataToSave=[packet.http.request_full_uri, packet.ip.src, packet.http._ws_expert_message, packet.http.user_agent]
    HTTPdb(dataToSave,cursor,db)

def sniff():
    print("_________________________________\n")
    print("Network Sniffer")
    print("Press CTRL+C at any time to exit\n")
    time.sleep(0.5)
    with sqlite3.connect("info.sqlite3") as db: cursor = db.cursor()#This creates a connection to the database

    try:
        wireTap = LiveCapture(interface='eth0')
        for packet in wireTap.sniff_continuously():
            if packet.highest_layer=="URLENCODED-FORM": #For html web form
                getHTTPinfo(packet,cursor,db,str(packet['urlencoded-form']))
                print(packet['urlencoded-form'])
            elif packet.highest_layer=="HTTP": #For get requests
                try:
                    if packet.http.request_method=="GET":   getHTTPinfo(packet,cursor,db)
                except AttributeError:  pass #Not a get request
            elif packet.highest_layer=="DATA-TEXT-LINES": #For recieving html
                print("Protocol",packet.http._ws_expert_message)
                print(packet['DATA-TEXT-LINES'])
                HTTPdb([packet.http._ws_expert_message,str(packet['DATA-TEXT-LINES'])],cursor,db)
                
            elif packet.highest_layer=="DNS":
                try:
                    if packet.dns.resp_name:
                        print("DNS Response from",packet.ip.src,"for",packet.dns.resp_name)
                        DNSdb([packet.ip.src,"response",packet.dns.resp_name],cursor,db)
                except AttributeError:
                    print("DNS Request from",packet.ip.src,"for",packet.dns.qry_name)
                    DNSdb([packet.ip.src,"request",packet.dns.qry_name],cursor,db)
    except (KeyboardInterrupt): 
        db.close()
        pass