#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        Cytoscape_2_Json.py [python3]
#
# Purpose:     This module will provide function to convert the cytoscapte pickle
#              file to Json file.
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

# find the case file list in the folder
caseFileList = glob.glob(os.path.join(DATA_FOLDER, "case*"))
print('---')
print(caseFileList)
linkFileList = glob.glob(os.path.join(DATA_FOLDER, "linked*"))
print('---')
print(linkFileList)
subFileList = glob.glob(os.path.join(DATA_FOLDER, "subgraphs*"))
print('---')
print(subFileList)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def caseCvt(filePath, outPutDir):
    """ Convert the case_* file to the json file.
        Args:
            filePath (Str): Case source data file path.
            outPutDir (Str): Output directory path.
    """
    with open(filePath, 'rb') as handle:
        subgraph_collection = pickle.load(handle)
    fileName = 'case'+filePath.split('case')[-1]

    rstFolder = os.path.join(outPutDir, 'case')
    if not os.path.exists(rstFolder):
        os.mkdir(rstFolder)

    fileName = os.path.join(outPutDir, 'case', fileName)
    with open(fileName+'._filtered_new_columns.json', 'w') as f:
        ar = []
        nodes = []
        edges = []
        lst = subgraph_collection

        with open(fileName+'.json', 'w') as f2:    
            parentid = "G" + str(0)
            g = lst
            graphattr = lst.graph
            #graphattr = g.snort
            graphattr["id"] = parentid
            graphattr["score"] = g.score if hasattr(g, 'score') else 0
            graphattr["consequences"] = g.consequences if hasattr(g, 'consequences') else []
            graphattr["num_components"] = g.num_components if hasattr(g, 'num_components') else []
            graphattr["max_in_degree"] = g.max_in_degree if hasattr(g, 'max_in_degree') else []
            graphattr["max_out_degree"] = g.max_out_degree if hasattr(g, 'max_out_degree') else []
            graphattr["num_events"] = g.num_events if hasattr(g, 'num_events') else []
            nodes.append({"data": graphattr})
            cydata = nx.readwrite.json_graph.cytoscape_data(g)
            ar.append(cydata)
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
                            geoMatch = geolite2.lookup(n['data']['id'])
                            n['data']['geo'] = [str(geoMatch.country), str(geoMatch.location)] if geoMatch else ['unknown', '(na,na)']
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


def main():
    if not os.path.exists(RST_FOLDER):
        os.mkdir(RST_FOLDER)
    # Generate the case result.
    for filePath in caseFileList:
        caseCvt(filePath, RST_FOLDER)

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()





exit()










    



#fileName = 'windows'
#fileName = 'snort'
#fileName = 'linked'

#fileName = 'Files_for_visualization/linked_subgraphs_all_logs_sep_2019'
#fileName = 'Files_for_visualization/linked_subgraphs_snort_forti_june_2020'
#fileName = 'Files_for_visualization/linked_subgraphs_snort_forti_sep_2019'
#fileName = 'Files_for_visualization/linked_subgraphs_win_forti_june_2020'
#fileName = 'Files_for_visualization/linked_subgraphs_win_forti_sep_2019'
#fileName = 'Files_for_visualization/subgraphs_fortinet_june_2020'
#fileName = 'Files_for_visualization/subgraphs_snort_june_2020'
#fileName = 'Files_for_visualization/subgraphs_snort_sep_2019'
#fileName = 'Files_for_visualization/subgraphs_windows_june_2020'
#fileName = 'Files_for_visualization/sugraphs_fortinet_sep_2019'
#fileName = 'October/case_4'
#fileName = 'October/case_5_1'
fileName = 'October/case_12'
#fileName = 'Files_for_visualization/linked_subgraphs_win_snort_sep_2019'


# read the dictionary containing 3 lists of subgraphs for snort , fortinet and windows
# nx MultiDiGraph
#with open('result_sep_2019_Hongwei.pickle', 'rb') as handle:
#with open(fileName+'_filtered_new.pkl', 'rb') as handle:
#    subgraph_collection = pickle.load(handle)
#with open(fileName+'_filtered_new_columns.pkl', 'rb') as handle:
with open(fileName, 'rb') as handle:
    subgraph_collection = pickle.load(handle)

# dump as json to file
#with open('result_sep_2019_Hongwei.json', 'w') as f:
with open(fileName+'._filtered_new_columns.json', 'w') as f:
#with open(fileName+'_filtered_new.json', 'w') as f:
#with open(fileName+'_filtered_new_columns.json', 'w') as f:
  ar = []
  nodes = []
  edges = []
  lst = subgraph_collection

  with open(fileName+'.json', 'w') as f2:    
    parentid = "G" + str(0)
    # print(parentid, g.score, g.consequences)
    g = lst
    graphattr = lst.graph
    
    #graphattr = g.snort
    graphattr["id"] = parentid
    if hasattr(g, 'score'):
      graphattr["score"] = g.score
    else: 
      graphattr["score"]= 0

    if hasattr(g, 'consequences'):
      graphattr["consequences"] = g.consequences
    else: 
      graphattr["consequences"] = []
    
    if hasattr(g, 'num_components'):
      graphattr["num_components"] = g.num_components
    else: 
      graphattr["num_components"] = []
    
    if hasattr(g, 'max_in_degree'):
      graphattr["max_in_degree"] = g.max_in_degree
    else: 
      graphattr["max_in_degree"] = []

    if hasattr(g, 'max_out_degree'):
      graphattr["max_out_degree"] = g.max_out_degree
    else: 
      graphattr["max_out_degree"] = []

    if hasattr(g, 'num_events'):
      graphattr["num_events"] = g.num_events
    else: 
      graphattr["num_events"] = []

    nodes.append({
        "data": graphattr
    })
    
    cydata = nx.readwrite.json_graph.cytoscape_data(g)
    # print(cydata)
    ar.append(cydata)
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
      #if ('linked' in fileName):
      if (False):
        e["data"]['t_port_values'] = list(e['data']['t_port_values'])
      else:
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
    print(cy)
    f2.write(json.dumps(cy))
  # write array of sub graphs
f.write(json.dumps(ar))
  # f.write("\n")
