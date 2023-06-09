import requests
import pandas as pd
import json
import matplotlib.pyplot as plt
    
#retrieve the base score using the new nvd API     
def get_cvedetails_newapi(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    r = requests.get(url)
    data = r.json()
    # Extract baseScore value
    base_score = data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]

    # Print baseScore value
    # print("New Base Score:", base_score)
    return{base_score}


def get_epss_scores(cve_list):
    epss_scores = {}
    
    for cve in cve_list:
        try:
            #get the EPSS Score from the FIRST EPSS API
            response = requests.get('https://api.first.org/data/v1/epss/?cve=' + cve.strip())
            if response.status_code == 200:
                data = response.json()
                #print(data)
                
                for item in data['data']:
                  cve = item["cve"]
                  epss = item["epss"]
                  percentile = item["percentile"]
                  new_base_score = get_cvedetails_newapi(cve)
                  
                  epss_scores[cve] = {
                    'epss': epss,
                    'new_base_score': new_base_score
                  }
                  
                  print(f"CVE: {cve}, EPSS Score: {epss}, Percentile: {percentile}, New Base Score {new_base_score}")
            else:
                epss_scores[cve] = 'Error: Status code ' + str(response.status_code)
        except Exception as e:
            epss_scores[cve] = 'Error: ' + str(e)
    
    return epss_scores

def plot_epss_vs_new_base_score(epss_scores):
    epss_values = []
    new_base_score_values = []
    
    for cve, score in epss_scores.items():
        #print(f"CVE: {cve}, EPSS Score: {score}")
        epss_values.append(float(score['epss']))
        # convert set to iterable list
        new_base_list = list(score['new_base_score'])
        new_base_score_values.append(float(new_base_list[0])) 
        
    plt.scatter(epss_values, new_base_score_values)
    plt.xlabel('EPSS (%)')
    plt.ylabel('New Base Score')
    plt.title('EPSS vs Base Score')
    plt.show()    
       


def read_cve_from_excel(filename, sheet_name, column_name):
    df = pd.read_excel(filename, sheet_name=sheet_name)
    cve_list = df[column_name].tolist()
    return cve_list


def main():
    filename = 'Book1.xlsx'
    sheet_name = 'Sheet1'
    column_name = 'CVEs'
        
    cve_list = read_cve_from_excel(filename, sheet_name, column_name)
    epss_scores = get_epss_scores(cve_list)
    plot_epss_vs_new_base_score(epss_scores)
    

if __name__ == "__main__":
    main()
