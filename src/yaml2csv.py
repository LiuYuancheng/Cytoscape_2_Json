#Purpose:     This module will provide functions to convert urls yaml file to csv file

# pip install pyyaml
import yaml
import csv

stream = open("urls.yaml", 'r')
dictionary = yaml.load_all(stream)
count = 0
# Change the csv sequence in the header list
headList = ['url', 'name', 'category', 'subcategory',
            'description', 'reporter', 'BTC', 'ETH']

# open the file in the write mode under UTF-8 encode
print(">> Start processing")
with open('urls.csv', 'w', encoding='UTF8', newline='') as f:
    # create the csv writer
    writer = csv.writer(f)
    writer.writerow(headList)
    for element in dictionary:
        for doc in element:
            #print(doc)
            count += 1
            row = []
            for key in headList:
                msg = doc[key] if key in doc.keys() else ''
                if (key == 'BTC' or key == 'ETH') and 'addresses' in doc.keys():
                    msg = doc['addresses'][key] if key in doc['addresses'].keys() else ''
                row.append(msg)
            writer.writerow(row)

print(">> Finished parse %s lines" % str(count))
