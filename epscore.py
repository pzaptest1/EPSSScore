import requests
import pandas as pd

def get_epss_scores(cve_list):
    epss_scores = {}
    
    for cve in cve_list:
        try:
            response = requests.get('https://api.first.org/data/v1/epss/?cve=' + cve.strip())
            if response.status_code == 200:
                data = response.json()
#                print(data)
                
                for item in data['data']:
                  cve = item["cve"]
                  epss = item["epss"]
                  percentile = item["percentile"]
                  print(f"CVE: {cve}, EPSS Score: {epss}, Percentile: {percentile}")
            else:
                epss_scores[cve] = 'Error: Status code ' + str(response.status_code)
        except Exception as e:
            epss_scores[cve] = 'Error: ' + str(e)
    
    return epss_scores


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
    
    for cve, score in epss_scores.items():
        print(f"CVE: {cve}, EPSS Score: {score}")


if __name__ == "__main__":
    main()
