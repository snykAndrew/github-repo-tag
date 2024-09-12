import argparse
import snyk
import os
from urllib.parse import quote
import http
import json

'''
Description: Program meant to:
 query Snyk Projects
 query types of targets in orgs
 tag github with those targets to run enforcement
'''
token = os.getenv('SNYK_API_TOKEN') # Set your API token as an environment variable
apiVersion = "2024-04-11~beta"  # Set the API version. Needs ~beta endpoint at stated version or later
tries = 4  # Number of retries
delay = 1  # Delay between retries
backoff = 2  # Backoff factor

all_remote_repo_urls = []

remote_code_repos = []
remote_os_repos = []
remote_iac_repos = []

def search_json(json_obj, search_string):
    if isinstance(json_obj, dict):
        for key, value in json_obj.items():
            if search_json(value, search_string):
                return True
    elif isinstance(json_obj, list):
        for item in json_obj:
            if search_json(item, search_string):
                return True
    elif isinstance(json_obj, str):
        if search_string in json_obj:
            return True
    return False

def get_org_projects(org_name=None, org_id=None, remote_repo_url=None, project_name=None, project_id=None, branch=None):
    client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff)  # Context switch the client to model-based
    organizations = client.organizations.all()
    if org_id is None:
        org_id = [o.id for o in organizations if org_name in o.name][0] # Grab org_id from first match
    projects = client.organizations.get(org_id).projects.all()
    if project_name is not None:
        projects = [p for p in projects if project_name in p.name]
    if remote_repo_url is not None:
        projects = [p for p in projects if remote_repo_url == p.remoteRepoUrl]
    if project_id is not None:
        projects = [p for p in projects if project_id == p.id]
    if branch is not None:
        projects = [p for p in projects if branch in p.branch]
    return projects

def get_org_projects():
    open_source_types = ['apk','cocoapods', 'composer', 'cpp', 'deb', 'golang', 'gradle', 'maven', 'npm', 'nuget', 'pip', 'pipenv', 'poetry', 'rubygems', 'sbt', 'swift', 'yarn']
    iac_types = ['cloudformationconfig', 'armconfig', 'dockerfile', 'helm', 'k8sconfig', 'terraformconfig']

    client = snyk.SnykClient(token, tries=tries, delay=delay, backoff=backoff)  # Context switch the client to model-based
    organizations = client.organizations.all()

    for org in organizations:
        if org.name == "SnykDemo":
            projects = org.projects.all()
            
            for project in projects:

                #if project.remoteRepoUrl == "https://github.com/snykMathesOrg/pythonMonoRepo":
                #if project.remoteRepoUrl is not None:
                if project.remoteRepoUrl not in all_remote_repo_urls:
                    all_remote_repo_urls.append(project.remoteRepoUrl)
                    
                if project.type == "sast":
                    if project.remoteRepoUrl not in remote_code_repos:
                        remote_code_repos.append(project.remoteRepoUrl)
                elif project.type in open_source_types:
                    if project.remoteRepoUrl not in remote_os_repos:
                        remote_os_repos.append(project.remoteRepoUrl)
                else:
                    if project.remoteRepoUrl not in remote_iac_repos:
                        remote_iac_repos.append(project.remoteRepoUrl)

def apply_github_tags():
    for repo_path in all_remote_repo_urls:
        if repo_path in remote_code_repos:
            set_repo_tag(repo_path, 'snykCode', 'true')
        else:
            set_repo_tag(repo_path, 'snykCode', 'false')

        if repo_path in remote_os_repos:
            set_repo_tag(repo_path, 'snykSCA', 'true')
        else:
            set_repo_tag(repo_path, 'snykSCA', 'false')

        if repo_path in remote_iac_repos:
            set_repo_tag(repo_path, 'snykIAC', 'true')
        else:
            set_repo_tag(repo_path, 'snykIAC', 'false')

def set_repo_tag(repo_path, tag, value):
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': "Bearer " + os.getenv('GITHUB_APITOKEN'),
        'User-Agent' : 'python script', 
        'X-GitHub-Api-Version': '2022-11-28'
    }

    if repo_path is not None:
        print("processing repo_path: " + repo_path)
        github_Org, repo_name = repo_path.split("/")[-2:]

        request_url = f"/repos/{github_Org}/{repo_name}/properties/values"
        conn = http.client.HTTPSConnection("api.github.com")
        custom_properties = {
            "properties": [
                { "property_name": tag, "value": value }
            ]
        }

        conn.request("PATCH", request_url , json.dumps(custom_properties), headers)
        response = conn.getresponse()
        response_data = response.read()
        conn.close()

    #probably want some messaging?

if __name__ == '__main__':
    # Parsing Command Line Arguments
    parser = argparse.ArgumentParser(
        description='Tag Github With Snyk Targets')
    # Required fields:

    orgs = []
    count = 0
    projects = get_org_projects()

    apply_github_tags()    

    print(f"--------------------")
    print(f'Collecting Project Types:')
    print(f"--------------------")

    # print count of issues with description of filter criteria from arguments
    print(f"\n")

    exit()