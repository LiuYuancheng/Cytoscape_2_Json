#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        Cytoscape_2_Json.py [python3]
#
# Purpose:     This module will provide functions to convert the cytoscape graph 
#              pickle file to JSON format file and find the geo location of the 
#              public IP address.
#              cytoscape link: https://cytoscape.org/
#              
# Author:      Liu Yuancheng
#
# version:     v_0.1
# Created:     2021/12/21
# Copyright:   Singtel Cyber Security Research & Development Laboratory
# License:     
#-----------------------------------------------------------------------------

import os
import glob
import json
import pickle
import networkx as nx
from networkx.readwrite import json_graph
#from geolite2 import geolite2
# for python 3 use pip3 install python-geoip-python3 to install: 
# https://stackoverflow.com/questions/32575666/python-geoip-does-not-work-on-python3-4
from geoip import geolite2

print("Current working directory is : %s" % os.getcwd())
dirpath = os.path.dirname(__file__)
print("Current source code location : %s" % dirpath)
APP_NAME = 'Cytoscape_2_Json_v0.1'

DATA_FOLDER = os.path.join(dirpath, "data")
RST_FOLDER = os.path.join(dirpath, "result")

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def caseCvt(filePath, outPutDir):
    """ Convert the 'case_*' file to the json file. Each case file should only have
        one cytoscape graph build in.
        Args:
            filePath (Str): Case* source data file path.
            outPutDir (Str): Output directory path. The result Json file will be 
				saved as 'outPutDir/case/filename.json'
    """
    subgraph_collection = None
    with open(filePath, 'rb') as handle:
        subgraph_collection = pickle.load(handle)
    fileName = 'case'+filePath.split('case')[-1]
    rstFolder = os.path.join(outPutDir, 'case')
    if not os.path.exists(rstFolder): os.mkdir(rstFolder)
    fileName = os.path.join(outPutDir, 'case', fileName) # output result file name.

    with open(fileName+'._filtered_new_columns.json', 'w') as f:
        ar = []     # data list 
        nodes = []  # nodes list 
        edges = []  # edges list
        with open(fileName+'.json', 'w') as f2:    
            parentid = "G" + str(0)
            graphattr = subgraph_collection.graph
            graphattr["id"] = parentid
            graphattr["score"] = subgraph_collection.score if hasattr(subgraph_collection, 'score') else 0
            graphattr["consequences"] = subgraph_collection.consequences if hasattr(subgraph_collection, 'consequences') else []
            graphattr["num_components"] = subgraph_collection.num_components if hasattr(subgraph_collection, 'num_components') else []
            graphattr["max_in_degree"] = subgraph_collection.max_in_degree if hasattr(subgraph_collection, 'max_in_degree') else []
            graphattr["max_out_degree"] = subgraph_collection.max_out_degree if hasattr(subgraph_collection, 'max_out_degree') else []
            graphattr["num_events"] = subgraph_collection.num_events if hasattr(subgraph_collection, 'num_events') else []
            nodes.append({"data": graphattr})
            cydata = nx.readwrite.json_graph.cytoscape_data(subgraph_collection)
            ar.append(cydata)
            # build the nodes info
            for n in cydata["elements"]["nodes"]:
                findRcd = False
                for nodep in nodes:
                    if n["data"]["id"] == nodep["data"]["id"]:
                        nodep["data"]["subgraphs"].append(parentid)
                        findRcd = True
                if not findRcd:
                    n["data"]["subgraphs"] = [parentid]
                    if(n['data']['id'].count('.')==3):
                    # Check whehter node Id is a IP: 
                        if(n['data']['id'] == '127.0.0.1' or '192.168.' in n['data']['id']):
                            # local IP addrss: 
                            n['data']['type'] = 'localIP'
                            n['data']['geo'] = ['local', '(na,na)']
                        else:
                            n['data']['type'] = 'pubIP'
                            geoMatch = geolite2.lookup(n['data']['id']) # find the public IP's geo location.
                            n['data']['geo'] = [str(geoMatch.country), str(geoMatch.location)] if geoMatch else ['unknown', '(na,na)']
                    else:
                        # The node is a APP/program
                        n['data']['type'] = 'other'
                        n['data']['geo'] = ['unknown', '(na,na)']
                    nodes.append(n)
            # build the edges info
            edgeCount = 0 
            for e in cydata["elements"]["edges"]:
                e["data"]["idx"] = edgeCount
                e["data"]['t_port_values'] = [str(e['data']['t_port_values'])]
                e["data"]['s_port_values'] = list(e['data']['s_port_values'])
                e["data"]['start_timestamp'] = str(e['data']['start_timestamp'])
                edgeCount += 1
                edges.append(e)
            ar.append(cydata)
            cy = {
                "elements": {
                    #"subgraphs": subgraphs,
                    "nodes": nodes,
                    "edges": edges
                }
            }
            #print(cy)
            f2.write(json.dumps(cy)) # create the finall result.
        f.write(json.dumps(ar)) #create the row processing data.

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def graphCvt(filePath, outPutDir, graphType='linked',graphName='snort_forti'):
    """ Convert the 'linked_*', 'subgraphs_*' file to the json file. The linked/
        subgrapshs files can have multiple cytoscape graphs build in.
        one cytoscape build in.
        Args:
            filePath (Str): Case* source data file path.
            outPutDir (Str): Output directory path. The result Json file will be 
                saved as outPutDir/filename.json
            graphType (str, optional): Identify what kind of data we want to convert. 
                Defaults to 'linked'.
            graphName (str, optional): Identify the graph name we want to find in the
                cytoscape file. Defaults to 'snort_forti'.
    """
    with open(filePath, 'rb') as handle:
        subgraph_collection = pickle.load(handle)
    fileName = graphType+filePath.split(graphType)[-1]
    rstFolder = os.path.join(outPutDir, graphType)
    if not os.path.exists(rstFolder): os.mkdir(rstFolder)
    fileName = os.path.join(outPutDir, graphType, fileName)
    with open(fileName+'_filtered_new_columns.json', 'w') as f:
        ar = []
        nodes = []
        edges = []
        with open(fileName+'_'+graphName+'.json', 'w') as f2:
            for idx, g in enumerate(subgraph_collection.get(graphName)):
                parentid = "G" + str(idx)
                graphattr = g.graph
                graphattr["id"] = parentid
                graphattr["score"] = g.score if hasattr(g, 'score') else 0
                graphattr["consequences"] = g.consequences if hasattr(g, 'consequences') else []
                graphattr["num_components"] = g.num_components if hasattr(g, 'num_components') else []       
                graphattr["max_in_degree"] = g.max_in_degree if hasattr(g, 'max_in_degree') else []
                graphattr["max_out_degree"] = g.max_out_degree if hasattr(g, 'max_out_degree') else []
                graphattr["num_events"] = g.num_events if hasattr(g, 'num_events') else []
                nodes.append({"data": graphattr})
                cydata = nx.readwrite.json_graph.cytoscape_data(g)
                # print(cydata)
                ar.append(cydata)
                for n in cydata["elements"]["nodes"]:
                    findRcd = False
                    for nodep in nodes:
                        if n["data"]["id"] == nodep["data"]["id"]:
                            #print('>>'+ str(nodep["data"]["subgraphs"]))
                            if hasattr(nodep["data"], 'subgraphs'):       
                                nodep["data"]["subgraphs"].append(parentid)
                            else:
                                n["data"]["subgraphs"] = [parentid]
                            findRcd = True
                    if not findRcd:
                        n["data"]["subgraphs"] = [parentid]
                        if(n['data']['id'].count('.')==3):
                            # Check whehter node Id is a IP: 
                            if(n['data']['id'] == '127.0.0.1' or '192.168.' in n['data']['id']):
                                # local IP addrss: 
                                n['data']['type'] = 'localIP'
                                n['data']['geo'] = ['local', '(na,na)']
                            else:
                                n['data']['type'] = 'pubIP'
                                # find the geo info if it is a public IP
                                #ipbytes = .encode('utf-8')
                                geoMatch = geolite2.lookup(n['data']['id'])
                                if geoMatch: 
                                    n['data']['geo'] = [str(geoMatch.country), str(geoMatch.location)]
                                else:
                                    n['data']['geo'] = ['unknown', '(na,na)']
                    else:
                        # The node is a APP/program
                        n['data']['type'] = 'other'
                        n['data']['geo'] = ['unknown', '(na,na)']
                    nodes.append(n)
                edgeCount = 0 
                for e in cydata["elements"]["edges"]:
                    e["data"]["idx"] = edgeCount
                    e["data"]['t_port_values'] = [str(e['data']['t_port_values'])]
                    e["data"]['s_port_values'] = list(e['data']['s_port_values'])
                    e["data"]['start_timestamp'] = str(e['data']['start_timestamp'])
                    edgeCount += 1
                    edges.append(e)
            ar.append(cydata)
            cy = {
                "elements": {
                    #"subgraphs": subgraphs,
                    "nodes": nodes,
                    "edges": edges
                }
            }
            #print(cy)
            f2.write(json.dumps(cy))
        f.write(json.dumps(ar))

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():

    if not os.path.exists(RST_FOLDER):
        os.mkdir(RST_FOLDER)
    # find the case file list in the folder
    print(">> Process the case files: ")
    caseFileList = glob.glob(os.path.join(DATA_FOLDER, "case*"))
    print(caseFileList)
    # Generate the case result.
    for filePath in caseFileList:
        caseCvt(filePath, RST_FOLDER)

    print(">> Process the linked files: ")
    linkFileList = glob.glob(os.path.join(DATA_FOLDER, "linked*"))
    print(linkFileList)
    for filePath in linkFileList:
        graphCvt(filePath, RST_FOLDER, graphType='linked', graphName='snort_forti')
    
    print(">> Process the subgraphs files: ")
    subFileList = glob.glob(os.path.join(DATA_FOLDER, "subgraphs*"))
    print(subFileList)
    for filePath in subFileList:
        graphCvt(filePath, RST_FOLDER, graphType='subgraphs', graphName='fortinet')
    
    print(">> Finished")

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
