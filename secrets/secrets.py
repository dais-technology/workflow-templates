
import boto3
import base64
from base64 import b64encode
from nacl import encoding, public
from botocore.exceptions import ClientError
import os

def list_all_repos(token):
  headers = {"Authorization": f"Bearer {token}"}
  page = 1
  url = f'https://api.github.com/orgs/dais-technology/repos?per_page=100&page={page}'
  resp = requests.get(url=url, headers=headers)
  data = resp.json() 
  repos = []
  hasMore = True
  while len(data) > 0:
    for item in data:
      repos.append({"name": item['name'], "id": item['id']})
    page = page + 1
    url = f'https://api.github.com/orgs/dais-technology/repos?per_page=100&page={page}'  
    resp = requests.get(url=url, headers=headers)
    data = resp.json()
  return repos

def list_all_secrets(token):
  headers = {"Authorization": f"Bearer {token}"}
  page = 1
  url = f'https://api.github.com/orgs/dais-technology/actions/secrets?per_page=100&page={page}'  
  resp = requests.get(url=url, headers=headers)
  data = resp.json() 
  allSecrets = []
  hasMore = True
  secrets = data['secrets']
  while len(secrets) > 0:
    for secret in secrets:
      allSecrets.append(secret['name'])
    page = page + 1
    url = f'https://api.github.com/orgs/dais-technology/actions/secrets?per_page=100&page={page}'  
    resp = requests.get(url=url, headers=headers)
    data = resp.json()
    secrets = data['secrets']
  return allSecrets

def secretExists(token, repository_id, env, secret):
  headers = {"Authorization": f"Bearer {token}"}
  url = f'https://api.github.com/repositories/{repository_id}/environments/dev/secrets/{secret}' 
  resp = requests.get(url=url, headers=headers)
  data = resp.json()
  if 'message' in data:
    return False
  else:
    return True

def envExists(token, repository_id, env):
  headers = {"Authorization": f"Bearer {token}"}
  url = f'https://api.github.com/repositories/{repository_id}/environments/dev' 
  resp = requests.get(url=url, headers=headers)
  data = resp.json()
  if 'message' in data:
    return False
  else:
    return True

def create_env(token, repository_id, environment_name):
  headers = {"Authorization": f"Bearer {token}"}
  url = f'https://api.github.com/repositories/{repository_id}/environments/{environment_name}'
  resp = requests.put(url=url, headers=headers)


def get_public_key(token, repository_id, environment_name):
  url = f'https://api.github.com/repositories/{repository_id}/environments/{environment_name}/secrets/public-key'
  resp = requests.get(url=url, headers=headers)
  return resp.json()
  
def encrypt(public_key: str, secret_value: str) -> str:
  """Encrypt a Unicode string using the public key."""
  public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
  sealed_box = public.SealedBox(public_key)
  encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
  return b64encode(encrypted).decode("utf-8")

def create_secret(token, repository_id, environment_name, secret_name, secret_value):
  headers = {"Authorization": f"Bearer {token}"}
  pub_key = get_public_key(token, repository_id, environment_name)
  key_id = pub_key['key_id']
  encrypted_value = encrypt(pub_key['key'], secret_value)
  print(f"Value is {secret_value}")
  print(f"Encrypted Value is {encrypted_value}")
  payload = {"encrypted_value":f"{encrypted_value}","key_id":f"{key_id}"}
  url = f'https://api.github.com/repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}'
  resp = requests.put(url=url, headers=headers, data=json.dumps(payload))

def get_secret(env, name):    
  secret_name = f"{env}/github/{name}"
  region_name = "us-west-2"
  session = boto3.session.Session()
  client = session.client(
      service_name='secretsmanager',
      region_name=region_name
  )
  get_secret_value_response = client.get_secret_value(
      SecretId=secret_name
  )
  return  get_secret_value_response['SecretString']

token = os.environ['GITHUB_TOKEN']

my_repos = list_all_repos(token)
environment_name = 'dev'
found = False
repo_count = 0
for repo in my_repos:
  if repo['name'] != 'workflow-templates' and found == False:
      repo_count = repo_count + 1
      print(f"Repo count = {repo_count}")
      print(repo['name'])
      continue
  else:
    found = True
  all_secrets = list_all_secrets(token)
  repository_id = repo['id']
  repository_name = repo['name']
  create_env(token, repository_id, environment_name)
  for secret in all_secrets:
    created = secretExists(token, repository_id, environment_name, secret)
    if not created:
      print(f'Secret {secret} not found in environment {environment_name}, repostory {repository_name}, creating...')
      secret_value = get_secret(environment_name, secret)
      create_secret(token, repository_id, environment_name, secret, secret_value)
      print(f'Secret {secret} created.')
    else:
      print(f'Secret {secret} found in environment {environment_name}, repostory {repository_name}, nothing to do.')