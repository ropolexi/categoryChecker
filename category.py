import ollama
import requests
import json
import time
from deso_sdk import DeSoDexClient
from deso_sdk  import base58_check_encode
from pprint import pprint
import datetime
import logging
import urllib.parse
from pathlib import Path


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

seed_phrase_or_hex="" #dont share this

base_dir = Path.cwd()
img_path= base_dir / "img"
img_path.mkdir(parents=True, exist_ok=True)
stats={}

model_name = "gemma3:12b"
BASE_URL = "https://node.deso.org"
local_domain="http://192.168.8.107:18001"

REMOTE_API = False
HAS_LOCAL_NODE_WITH_INDEXING = False
HAS_LOCAL_NODE_WITHOUT_INDEXING = True

api_url = BASE_URL+"/api/v0/"
local_url= local_domain +"/api/v0/"

# Global variables for thread control
stop_flag = True
calculation_thread = None
app_close=False
update_time_interval=5
if REMOTE_API:
    HAS_LOCAL_NODE_WITHOUT_INDEXING= False
    HAS_LOCAL_NODE_WITH_INDEXING = False
    update_time_interval=30

else:
    if HAS_LOCAL_NODE_WITHOUT_INDEXING:
        HAS_LOCAL_NODE_WITH_INDEXING = False

    if HAS_LOCAL_NODE_WITH_INDEXING:
        HAS_LOCAL_NODE_WITHOUT_INDEXING = False

print(f"HAS_LOCAL_NODE_WITHOUT_INDEXING:{HAS_LOCAL_NODE_WITHOUT_INDEXING}")
print(f"HAS_LOCAL_NODE_WITH_INDEXING:{HAS_LOCAL_NODE_WITH_INDEXING}")


client = DeSoDexClient(
    is_testnet=False,
    seed_phrase_or_hex=seed_phrase_or_hex,
    passphrase="",
    node_url=BASE_URL if REMOTE_API else local_domain
)

ALLOWED = {"people", "nature", "abstract","food" ,"technology" ,"animals","christmas", "nsfw"}

def save_to_json(data, filename):
  try:
    with open(filename, 'w') as f:  # 'w' mode: write (overwrites existing file)
      json.dump(data, f, indent=4)  # indent for pretty formatting
    print(f"Data saved to {filename}")
  except TypeError as e:
    print(f"Error: Data is not JSON serializable: {e}")
  except Exception as e:
    print(f"Error saving to file: {e}")

def load_from_json(filename):
  try:
    with open(filename, 'r') as f:  # 'r' mode: read
      data = json.load(f)
    print(f"Data loaded from {filename}")
    return data
  except FileNotFoundError:
    print(f"Error: File not found: {filename}")
    return None  # Important: Return None if file not found
  except json.JSONDecodeError as e:
    print(f"Error decoding JSON in {filename}: {e}")
    return None # Important: Return None if JSON is invalid
  except Exception as e:
    print(f"Error loading from file: {e}")
    return None

def api_get(endpoint, payload=None):
    try:
        if REMOTE_API:
            response = requests.post(api_url + endpoint, json=payload)
        else:
            if HAS_LOCAL_NODE_WITHOUT_INDEXING:
                if endpoint=="get-notifications":
                    print("---Using remote node---")
                    response = requests.post(api_url + endpoint, json=payload)
                    print("--------End------------")
                else:
                    response = requests.post(local_url + endpoint, json=payload)
            if HAS_LOCAL_NODE_WITH_INDEXING:
                response = requests.post(local_url + endpoint, json=payload)
            
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"API Error: {e}")
        return None

def create_post(body,parent_post_hash_hex,category=""):
    logging.info("\n---- Submit Post ----")
    try:
        logging.info('Constructing submit-post txn...')
        post_response = client.submit_post(
            updater_public_key_base58check=bot_public_key,
            body=body,
            parent_post_hash_hex=parent_post_hash_hex,  # Example parent post hash
            title="",
            image_urls=[],
            video_urls=[],
            post_extra_data={"Node": "1","is_bot":"true","category":category},
            min_fee_rate_nanos_per_kb=1000,
            is_hidden=False,
            in_tutorial=False
        )
        logging.info('Signing and submitting txn...')
        submitted_txn_response = client.sign_and_submit_txn(post_response)
        txn_hash = submitted_txn_response['TxnHashHex']
        
        logging.info('SUCCESS!')
        return 1
    except Exception as e:
        logging.error(f"ERROR: Submit post call failed: {e}")
        return 0

def get_single_profile(Username,PublicKeyBase58Check=""):
    payload = {
        "NoErrorOnMissing": False,
        "PublicKeyBase58Check": PublicKeyBase58Check,
        "Username": Username
    }
    data = api_get("get-single-profile", payload)
    return data

bot_public_key = base58_check_encode(client.deso_keypair.public_key, False)
bot_username = get_single_profile("",bot_public_key)["Profile"]["Username"]
if bot_username is None:
    print("Error,bot username can not get. exit")
    exit()

def get_posts_stateless(ReaderPublicKeyBase58Check,NumToFetch=50):
    payload = {
        "AddGlobalFeedBool":True,
        "FetchSubcomments":False,
        "GetPostsByDESO":False,
        "GetPostsForFollowFeed":False,
        "GetPostsForGlobalWhitelist":False,
        "MediaRequired":False,
        "NumToFetch":NumToFetch,
        "OrderBy":"newest",
        "PostContent":"",
        "PostHashHex":"",
        "PostsByDESOMinutesLookback":0,
        "ReaderPublicKeyBase58Check":ReaderPublicKeyBase58Check,
        "StartTstampSecs":None
    }
    data = api_get("get-posts-stateless", payload)
    return data  


def categorize_image_with_confidence(image_path: str):
    prompt = (
        "Classify the image.\n"
        "Rules:\n"
        "- category must be one of: people, nature, abstract, food ,technology ,animals ,christmas, nsfw\n"
        "- confidence must be an integer from 0 to 100\n"
        "- output ONLY valid JSON\n"
        "- no extra text\n\n"
        "Format exactly:\n"
        "{\"category\":\"nature\",\"confidence\":60}"
    )

    response = ollama.chat(
        model=model_name,
        messages=[{
            "role": "user",
            "content": prompt,
            "images": [image_path],
        }],
        format="json",
        options={
            "temperature": 0,
            "format": "json"
        }
    )

    try:
        data = json.loads(response["message"]["content"])
        category = data["category"]
        confidence = int(data["confidence"])

        if category not in ALLOWED:
            raise ValueError("Invalid category")

        confidence = max(0, min(confidence, 100))
        return category, confidence

    except Exception:
        # absolute fallback
        print(response["message"]["content"])
        return "abstract", 0

def extract_image_url(info_string):
    parsed_url = urllib.parse.urlparse(info_string)
    path = parsed_url.path
    filename = path.split('/')[-1]  # Get the last part of the path
    return filename
  
def run():
    max_nano_ts=0
    last_nano_tx=0
    nano_ts=0
    post_id_list=[]
    last_run = datetime.datetime.now() - datetime.timedelta(hours=12)

    while(True):
        try:

            if result:=load_from_json("postIdList_LIKE.json"):
                post_id_list=result
            if result:=load_from_json("stats.json"):
                stats=result

            while(True):
                logging.debug("Checking feed")
                if results:=get_posts_stateless(bot_public_key,NumToFetch=10):
                    
                    for post in results["PostsFound"]:
                        logging.debug(post["TimestampNanos"])
                        nano_ts=post["TimestampNanos"]
                        if nano_ts > max_nano_ts:
                            max_nano_ts = nano_ts
                        if nano_ts<=last_nano_tx:
                            logging.debug("Old feed")
                            break
                        if post["PostHashHex"] not in post_id_list:
                            ts=nano_ts/1e9
                            dt=datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                            
                            post_id_list.append(post["PostHashHex"])
                            save_to_json(post_id_list,"postIdList_LIKE.json")
                          
                            if post["ImageURLs"]!=None and len(post["ImageURLs"])>0:
                                logging.info(f"UTC Time:{dt}")
                                logging.info(f"Username:{post['ProfileEntryResponse']['Username']}")
                                logging.info(post["Body"])
                                image_url=post["ImageURLs"][0]
                                logging.info(f"Image URL:{image_url}")
                                image_file_name= extract_image_url(image_url)
                                print(image_file_name)
                                image_save_path = img_path / image_file_name

                                if not image_save_path.exists():
                                    logging.info("Image not found locally. Downloading...")
                                    image_data = requests.get(image_url).content
                                    with open(image_save_path, 'wb') as handler:
                                        handler.write(image_data)
                                else:
                                    logging.info("Image already exists. Skipping download.")                              
                                
                                category, confidence = categorize_image_with_confidence(image_save_path)
                                stats[category]=stats.get(category,0)+1
                                logging.info(f"category: {category}, confidence: {confidence}%")
                                reply_body=f"category: {category}, confidence: {confidence}%"
                                create_post(reply_body,post["PostHashHex"],category)
                                print(stats)
                                save_to_json(stats,"stats.json")
                                logging.info("==============================")
                    if max_nano_ts>last_nano_tx:
                        last_nano_tx=max_nano_ts
                time.sleep(update_time_interval)
                info_body="✍️ Category Checker Service Status\n"
    
                for key in stats:
                    info_body +=f"* {key}: {stats[key]}\n"
                info_body += f"Total images processed: {sum(stats.values())}\n"
                
    
                now = datetime.datetime.now()
    
                if now - last_run >= datetime.timedelta(hours=12):
                    print(info_body)
                    create_post(info_body,"")
                    last_run = now
        except Exception as e:
            logging.error(e)
            time.sleep(1)

run()
