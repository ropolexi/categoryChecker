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
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image
import time
import re
import os


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

seed_phrase_or_hex="" #dont share this
# seed_phrase_or_hex = os.environ.get("SEED_PHRASE")

# if seed_phrase_or_hex is None:
#     print("Error: SEED_PHRASE environment variable not set.")
#     exit()

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
calculation_thread = None
update_time_interval=10
last_run = datetime.datetime.now() - datetime.timedelta(minutes=6)
notify_user_list={}
post_id_list=[]
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

ALLOWED = {"people", "nature", "abstract","food" ,"technology" ,"animals","christmas","text","vehicles","sports","celebrations","gardening","electronics","mature","nsfw"}
ALLOWED_TYPES = {"image", "video"}

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
    allowed_str=", ".join(ALLOWED)
    prompt = (
        "Classify the image.\n"
        "Rules:\n"
        "- category must be one of: " + allowed_str + "\n"
        "- confidence must be an integer from 0 to 100\n"
        "- output ONLY valid JSON\n"
        "- no extra text\n\n"
        "Format exactly:\n"
        "{\"category\":\"nature\",\"confidence\":60}"
    )
    print(prompt)

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

def extract_image_from_video_advance(url):
    options = Options()
    options.add_argument("--autoplay-policy=no-user-gesture-required")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-notifications")
    options.add_argument("--headless=new")
    options.add_argument("--incognito")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-popup-blocking")
    #options.add_argument("--user-data-dir=%TEMP%\\selenium_profile")
    prefs = {
        "download.default_directory": "NUL",
        "download.prompt_for_download": False,
        "safebrowsing.enabled": True
    }
    options.add_experimental_option("prefs", prefs)
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1280, 720)
    driver.get(url)

    wait = WebDriverWait(driver, 20)

    # Wait for the video element to appear
    video = wait.until(
        EC.presence_of_element_located((By.TAG_NAME, "video"))
    )

    # Scroll video into view
    driver.execute_script("arguments[0].scrollIntoView(true);", video)

    # Give the video time to load a frame
    time.sleep(3)

    # Take full-page screenshot
    driver.save_screenshot("page.png")

    # Crop only the video area
    location = video.location
    size = video.size

    image = Image.open("page.png")

    left = location["x"]
    top = location["y"]
    right = left + size["width"]
    bottom = top + size["height"]

    video_frame = image.crop((left, top, right, bottom))
    filename = "video_frame.jpg"
    video_frame.save(filename)

    print("Saved " + filename)
    
    driver.quit()
    return filename

def extract_image_url(info_string):
    parsed_url = urllib.parse.urlparse(info_string)
    path = parsed_url.path
    filename = path.split('/')[-1]  # Get the last part of the path
    return filename

def get_notifications(PublicKeyBase58Check,FetchStartIndex=-1,NumToFetch=1,FilteredOutNotificationCategories={}):
    payload = {
        "PublicKeyBase58Check": PublicKeyBase58Check,
        "FetchStartIndex": FetchStartIndex,
        "NumToFetch": NumToFetch,
        "FilteredOutNotificationCategories":FilteredOutNotificationCategories
    }
    data = api_get("get-notifications", payload)
    return data

def get_single_post(post_hash_hex, reader_public_key=None, fetch_parents=False, comment_offset=0, comment_limit=100, add_global_feed=False):
    payload = {
        "PostHashHex": post_hash_hex,
        "FetchParents": fetch_parents,
        "CommentOffset": comment_offset,
        "CommentLimit": comment_limit
    }
    if reader_public_key:
        payload["ReaderPublicKeyBase58Check"] = reader_public_key
    if add_global_feed:
        payload["AddGlobalFeedBool"] = add_global_feed
    data = api_get("get-single-post", payload)
    return data["PostFound"] if "PostFound" in data else None

def extract_category_and_subject(text):
    pattern = r"@CategoryChecker (notify|stop) (\w+) (\w+)"

    match = re.match(pattern, text)

    if match:
        command = match.group(1)  # "notify" or "stop"
        category_type = match.group(2)
        category = match.group(3)

        if category_type not in ALLOWED_TYPES or category not in ALLOWED:
            return None  # Invalid category or type

        status = command  # Status is "notify" or "stop"

        return {"category_type":category_type,"category": category,"status": status}
    else:
        return None

  
def notificationListener():
    global last_run,notify_user_list,post_id_list

    profile=get_single_profile("",bot_public_key)
 
    now = datetime.datetime.now() 
    logging.info(now)
    if now - last_run >= datetime.timedelta(minutes=2):
        last_run = now  
        logging.info("Checking notifications")

        result=get_notifications(profile["Profile"]["PublicKeyBase58Check"],NumToFetch=20,FilteredOutNotificationCategories={"dao coin":True,"user association":True, "post association":True,"post":False,"dao":True,"nft":True,"follow":True,"like":True,"diamond":True,"transfer":True})
        for notification in result["Notifications"]:
            for affectedkeys in notification["Metadata"]["AffectedPublicKeys"]:
                if affectedkeys["Metadata"]=="MentionedPublicKeyBase58Check":
                    if affectedkeys["PublicKeyBase58Check"]==profile["Profile"]["PublicKeyBase58Check"]:
                        postId=notification["Metadata"]["SubmitPostTxindexMetadata"]["PostHashBeingModifiedHex"]
                        if postId in post_id_list:
                            break
                        else:
                            post_id_list.append(postId)
                            save_to_json({"post_ids":post_id_list},"postIdList_thread.json")
                            logging.info(postId)
                            transactor=notification["Metadata"]["TransactorPublicKeyBase58Check"]
                            r=get_single_profile("",transactor)
                            if r is None:
                                break
                            username= r["Profile"]["Username"]
                            mentioned_post = get_single_post(postId,bot_public_key)
                            body=mentioned_post["Body"]
                        
                            logging.debug(f"username: {username}")
                            logging.debug(f"transactor: {transactor}")
                            logging.debug(f"body:\n{body}") 
                            status_res=extract_category_and_subject(body)
                            if status_res is None:
                                logging.debug("No valid notify command found or invalid category/type")
                                break
                            else:
                                command=status_res["status"]
                                if command=="notify":
                                    logging.info("Notify command found")
                                    category_type=status_res["category_type"]
                                    category=status_res["category"]
                                    logging.info(f"Notify command found: type:{category_type}, category:{category}")
                                    notify_user_list[category_type]=notify_user_list.get(category_type,{})
                                    notify_user_list[category_type][category]=notify_user_list[category_type].get(category,[])
                                    if transactor not in notify_user_list[category_type][category]:
                                        notify_user_list[category_type][category].append(transactor)
                                        save_to_json(notify_user_list,"notify_user_list.json")
                                        create_post(f"@{username} You will be notified for {category_type} category: {category}.",postId)
                                    else:
                                        create_post(f"@{username} You are already set to be notified for {category_type} category: {category}.",postId)
                                elif command=="stop":
                                    logging.info("Stop command found")
                                    category_type=status_res["category_type"]
                                    category=status_res["category"]
                                    logging.info(f"Stop command found: type:{category_type}, category:{category}")
                                    if category_type in notify_user_list:
                                        if category in notify_user_list[category_type]:
                                            if transactor in notify_user_list[category_type][category]:
                                                notify_user_list[category_type][category].remove(transactor)
                                                save_to_json(notify_user_list,"notify_user_list.json")
                                                create_post(f"@{username} You will NOT be notified for {category_type} category: {category}.",postId)

                            break

       
    
def run():
    global notify_user_list,post_id_list

    max_nano_ts=0
    last_nano_tx=0
    nano_ts=0
    post_id_list_feed=[]
  
    posts_count=0
    last_run_report = datetime.datetime.now()# - datetime.timedelta(hours=12)
    stats_video={}
    stats={}
    while(True):
        try:
            

            if result:=load_from_json("postIdList_LIKE.json"):
                post_id_list_feed=result
            if result:=load_from_json("stats.json"):
                stats=result
            if result:=load_from_json("stats_video.json"):
                stats_video=result

            if result:=load_from_json("postIdList_thread.json"):
                post_id_list=result["post_ids"]
            if result:=load_from_json("notify_user_list.json"):
                notify_user_list=result

            while(True):
                notificationListener()
                logging.debug("Checking feed")
                if results:=get_posts_stateless(bot_public_key,NumToFetch=20):
                    
                    for post in results["PostsFound"]:
                        logging.debug(post["TimestampNanos"])
                        nano_ts=post["TimestampNanos"]
                        if nano_ts > max_nano_ts:
                            max_nano_ts = nano_ts
                        if nano_ts<=last_nano_tx:
                            logging.debug("Old feed")
                            break
                        if post["PostHashHex"] not in post_id_list_feed:
                            ts=nano_ts/1e9
                            dt=datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                            
                            post_id_list_feed.append(post["PostHashHex"])
                            save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                            posts_count+=1
                            post_username=post['ProfileEntryResponse']['Username'] if post['ProfileEntryResponse']['Username'] is not None else "unknown"
                            logging.info(f"\n---- New Post #{posts_count} ----")
                            logging.info(f"UTC Time:{dt}")
                            logging.info(f"Username:{post_username}")
                            logging.info(f'PublicKeyBase58Check:{post['ProfileEntryResponse']["PublicKeyBase58Check"]}')
                            logging.info("=============Body==============")
                            logging.info(post["Body"])
                            logging.info("===============END=============")

                          
                            if post["VideoURLs"]!=None and len(post["VideoURLs"])>0:
                                video_url=post["VideoURLs"][0]
                                logging.info(f"Video URL:{video_url}")
                                if video_url!="":
                                    image_file_name= extract_image_from_video_advance(video_url)
                                    if image_file_name is None:
                                        logging.info("Failed to extract middle frame from video. Skipping post.")
                                        continue         
                                    
                                    category, confidence = categorize_image_with_confidence(image_file_name)
                                    stats_video[category]=stats_video.get(category,0)+1
                                    save_to_json(stats_video,"stats_video.json")
                                    logging.info(f"category: {category}, confidence: {confidence}%")
                                    reply_body=f"category: #{category} , confidence: {confidence}%"
                                    create_post(reply_body,post["PostHashHex"],category)
                                    users_list=[]
                                    if "video" in notify_user_list:
                                        if category in notify_user_list["video"]:
                                            users_list=notify_user_list["video"][category] 
                                    usernames_str=""
                                    for user_public_key in users_list:
                                        user = get_single_profile("",user_public_key)
                                        if user != None and "Profile" in user:
                                            if "Username" in user["Profile"]:
                                                if user["Profile"]["Username"] != None:
                                                    if post['ProfileEntryResponse']["PublicKeyBase58Check"]!=user_public_key:
                                                            usernames_str += "@"+user["Profile"]["Username"]+" "  
                                    if usernames_str!="":
                                        create_post(f"{usernames_str} Check out your interested video post by {post_username}, category: {category}",post["PostHashHex"])        
                                    print(stats_video)
                                    
                                    logging.info("==============================")

                            if post["ImageURLs"]!=None and len(post["ImageURLs"])>0:
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
                                save_to_json(stats,"stats.json")
                                logging.info(f"category: {category}, confidence: {confidence}%")
                                reply_body=f"category: #{category} , confidence: {confidence}%"
                                create_post(reply_body,post["PostHashHex"],category)
                                users_list=[]
                                if "image" in notify_user_list:
                                    if category in notify_user_list["image"]:
                                        users_list=notify_user_list["image"][category]

                                usernames_str=""

                                for user_public_key in users_list:
                                    user = get_single_profile("",user_public_key)
                                    if user != None and "Profile" in user:
                                        if "Username" in user["Profile"]:
                                            if user["Profile"]["Username"] != None:
                                                if post['ProfileEntryResponse']["PublicKeyBase58Check"]!=user_public_key:
                                                    usernames_str += "@"+user["Profile"]["Username"]+" "  
                                if usernames_str!="":
                                    create_post(f"{usernames_str} Check out your interested image post by {post_username}, category: {category}",post["PostHashHex"])      

                                print(stats)
                                
                                logging.info("==============================")
                    if max_nano_ts>last_nano_tx:
                        last_nano_tx=max_nano_ts
                
                info_body="✍️ Category Checker Service Status\n"

                sorted_stats = sorted(stats.items(), key=lambda item: item[1], reverse=True)
                info_body += "\n🖼️ Image Category Stats:\n"
                for key, value in sorted_stats:  # This is the crucial change: tuple unpacking
                    info_body += f"* {key}: {value}\n"
                info_body += f"Total images processed: {sum(stats.values())}\n"

                sorted_stats_video = sorted(stats_video.items(), key=lambda item: item[1], reverse=True)
                info_body += "\n🎥 Video Category Stats:\n"
                for key, value in sorted_stats_video:  # This is the crucial change: tuple unpacking
                    info_body += f"* {key}: {value}\n"
                info_body += f"Total videos processed: {sum(stats_video.values())}\n"
                print(info_body)
    
                now = datetime.datetime.now()
    
                if now - last_run_report >= datetime.timedelta(hours=3) and posts_count>100:
                    print(info_body)
                    create_post(info_body,"")
                    last_run_report = now
                    posts_count=0

                time.sleep(update_time_interval)
        except Exception as e:
            logging.error(e)
            time.sleep(1)

run()
