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
from urllib.parse import urlparse
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
import cv2
import unicodedata

# Configure logging with timestamp
logging.basicConfig(
    filename='categorize_app.log',
    format='%(asctime)s - %(levelname)s: %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'  # Optional: customize the timestamp format
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

seed_phrase_or_hex="" #dont share this
# seed_phrase_or_hex = os.environ.get("SEED_PHRASE")

# if seed_phrase_or_hex is None:
#     print("Error: SEED_PHRASE environment variable not set.")
#     exit()

base_dir = Path.cwd()
img_path= base_dir / "img"
img_path.mkdir(parents=True, exist_ok=True)
stats={}

# Posting and other Settings, update before running
#---------------------------------------------------------
text_detect_enable = True
process_videos = True
process_images = True
quote_post = True
global_notify = True
stats_calculate = True
#---------------------------------------------------------

model_name = "gemma3:12b"
BASE_URL = "https://node.deso.org"
#local_domain="http://192.168.8.107:18001"
local_domain="http://192.168.1.3:18001"
REMOTE_API = False
HAS_LOCAL_NODE_WITH_INDEXING = False
HAS_LOCAL_NODE_WITHOUT_INDEXING = True

api_url = BASE_URL+"/api/v0/"
local_url= local_domain +"/api/v0/"

# Global variables for thread control
calculation_thread = None
update_time_interval=1
last_run = datetime.datetime.now() - datetime.timedelta(minutes=6)
notify_user_list={}
post_id_list=[]
if REMOTE_API:
    HAS_LOCAL_NODE_WITHOUT_INDEXING= False
    HAS_LOCAL_NODE_WITH_INDEXING = False
    update_time_interval=60*5

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
SCAM_USERS={"DeSociaIWorIdRewards","FocusRewards","DeSocialWorIdValidator"}
VALID_USERS={"mcmarsh","CategoryChecker","Arnoud","DeSocialWorld","Exotica_S","WhaleDShark","NFTzToken","MyDeSoSpace","CryptoWebDigger"}
#ALLOWED = ["people", "nature", "abstract","food" ,"technology" ,"animals","christmas","text","vehicles","sports","celebrations","gardening","electronics","trading","art","girls","nsfw"]
ALLOWED = [
  "people",
  "nature",
  "food",
  "technology",
  "vehicles",
  "sports",
  "art",
  "text",
  "holidays",
  "abstract",
  "trading",
  "nsfw"
]

ALLOWED_TYPES = {"image", "video"}

def save_to_json(data, filename):
  try:
    with open(filename, 'w') as f:  # 'w' mode: write (overwrites existing file)
      json.dump(data, f, indent=4)  # indent for pretty formatting
    logging.info(f"Data saved to {filename}")
  except TypeError as e:
    logging.error(f"Error: Data is not JSON serializable: {e}")
  except Exception as e:
    logging.error(f"Error saving to file: {e}")

def load_from_json(filename):
  try:
    with open(filename, 'r') as f:  # 'r' mode: read
      data = json.load(f)
    logging.info(f"Data loaded from {filename}")
    return data
  except FileNotFoundError:
    logging.error(f"Error: File not found: {filename}")
    return None  # Important: Return None if file not found
  except json.JSONDecodeError as e:
    logging.error(f"Error decoding JSON in {filename}: {e}")
    return None # Important: Return None if JSON is invalid
  except Exception as e:
    logging.error(f"Error loading from file: {e}")
    return None
  

def api_get(endpoint, payload=None):
    try:
        if REMOTE_API:
            response = requests.post(api_url + endpoint, json=payload)
        else:
            if HAS_LOCAL_NODE_WITHOUT_INDEXING:
                if endpoint=="get-notifications":
                    logging.debug("---Using remote node---")
                    response = requests.post(api_url + endpoint, json=payload)
                    logging.debug("--------End------------")
                else:
                    response = requests.post(local_url + endpoint, json=payload)
            if HAS_LOCAL_NODE_WITH_INDEXING:
                response = requests.post(local_url + endpoint, json=payload)
            
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logging.error(f"API Error: {e}")
        return None

def create_quote_post(body,parent_post_hash_hex,category=[]):
    if quote_post==True:
        logging.info("\n---- Submit Quote Post ----")
        try:
            logging.info('Constructing submit-post txn...')
            post_response = client.submit_post(
                updater_public_key_base58check=bot_public_key,
                body=body,
                reposted_post_hash_hex=parent_post_hash_hex,
                title="",
                image_urls=[],
                video_urls=[],
                post_extra_data={"Node": "1","is_bot":"true","categories":json.dumps(category)},
                min_fee_rate_nanos_per_kb=1000,
                is_hidden=False,
                in_tutorial=False
            )
            logging.info('Signing and submitting txn...')
            submitted_txn_response = client.sign_and_submit_txn(post_response)
            txn_hash = submitted_txn_response['TxnHashHex']
            logging.debug(f"Txn Hash: {txn_hash}")
            logging.info('SUCCESS!')
            return 1
        except Exception as e:
            logging.error(f"ERROR: Submit post call failed: {e}")
            return 0
    
def create_post(body,parent_post_hash_hex,category=[]):
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
            post_extra_data={"Node": "1","is_bot":"true","categories":json.dumps(category)},
            min_fee_rate_nanos_per_kb=1000,
            is_hidden=False,
            in_tutorial=False
        )
        logging.info('Signing and submitting txn...')
        submitted_txn_response = client.sign_and_submit_txn(post_response)
        #client.wait_for_commitment_with_timeout(submitted_txn_response['TxnHashHex'], 5)
        txn_hash = submitted_txn_response['TxnHashHex']
        logging.debug(f"Txn Hash: {txn_hash}")
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
    logging.error("Error,bot username can not get. exit")
    exit()

def get_posts_stateless(ReaderPublicKeyBase58Check,NumToFetch=50,PostHashHex=""):
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
        "PostHashHex":PostHashHex,
        "PostsByDESOMinutesLookback":0,
        "ReaderPublicKeyBase58Check":ReaderPublicKeyBase58Check,
        "StartTstampSecs":None
    }
    data = api_get("get-posts-stateless", payload)
    return data  

def post_associations_counts(post_hash,AssociationType,AssociationValues):
    payload = {
        "AssociationType": AssociationType,
        "AssociationValues": AssociationValues,
        "PostHashHex": post_hash
    }
    data = api_get("post-associations/counts", payload)
    return data

def get_post_associations(post_hash, AssociationType,AssociationValue):
    payload = {
        "AssociationType": AssociationType,
        "AssociationValue": AssociationValue,
        "IncludeTransactorProfile": True,
        "Limit": 100,
        "PostHashHex": post_hash
    }
    data = api_get("post-associations/query", payload)
    return data

def create_post_associations(TransactorPublicKeyBase58Check,PostHashHex,AssociationType,AssociationValue,ExtraData={}):
    try:
        logging.info('Constructing create_post_associations txn...')
        payload = {
        "TransactorPublicKeyBase58Check": TransactorPublicKeyBase58Check,
        "PostHashHex": PostHashHex,
        "AppPublicKeyBase58Check": TransactorPublicKeyBase58Check,
        "AssociationType": AssociationType,
        "AssociationValue": AssociationValue,
        "ExtraData": ExtraData,
        "MinFeeRateNanosPerKB": 1000
        }
        logging.info(f'Payload: {payload}')
        post_response = api_get("post-associations/create", payload)
        logging.info('Signing and submitting txn...')
        submitted_txn_response = client.sign_and_submit_txn(post_response)
        #client.wait_for_commitment_with_timeout(submitted_txn_response['TxnHashHex'], 5)
        txn_hash = submitted_txn_response['TxnHashHex']
        logging.debug(f"Txn Hash: {txn_hash}")
        logging.info('SUCCESS!')
        
        return 1  
    except Exception as e:
        logging.error(f"ERROR: Submit post call failed: {e}")
        return 0

def categorize_image_with_confidence(image_path: str,text:str):
    allowed_str=", ".join(ALLOWED)
    prompt = (
        "Classify the image as accurately as possible.\n\n"
        "Image description or user text about the image:\n"
        "<<<" + text + ">>>\n\n"
        "Rules:\n"
        "- Choose ONE main category based on the most visually dominant subject.\n"
        "- Category MUST be from this list: " + allowed_str + "\n"
        "- Subcategory should be more specific than category when possible."
        "- If no specific subcategory exists, set subcategory equal to category."
        "- If multiple objects exist, prioritize the primary subject."
        "- If the image depicts a human-created or intentionally designed representation (e.g., painting, illustration, sculpture, installation), classify it as \"art\" even if it represents nature."
        "- Classify as \"nature\" ONLY when the scene is a real, unaltered natural environment or subject."
        "- If the image contains readable words, signs, or documents, prefer \"text\"."
        "- If the image contains explicit sexual content or nude art, use \"nsfw\"."
        "- Output ONLY valid JSON."
        "- Do NOT include explanations or extra text.\n\n"
        "Output format EXACTLY:\n"
        "{\"category\":\"category\",\"subcategory\":\"subcategory\"}"

    )
    logging.debug(prompt)

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
        logging.info(f"LLM Response Data: {data}")
        category = data["category"]
        subcategory = data["subcategory"]

        if category not in ALLOWED:
            category = ""

        return category,subcategory

    except Exception:
        # absolute fallback
        logging.error(response["message"]["content"])
        return "", ""



def text_category(body:str):
    if text_detect_enable ==True:
        logging.info("text clissification")   
        prompt = (
            "You are an automated text classification system.\n"
            "Your task is to classify the following Twitter/X-style post into exactly ONE of the categories listed below.\n"
            "\n"
            "Categories:\n"
            "- Scam – attempts to deceive users, phishing, fake giveaways, impersonation, crypto scams, suspicious links\n"
            "- Advertisement – marketing, sponsored content, product or service promotion, affiliate links\n"
            "- Politics – political parties, elections, politicians, public policy, government actions\n"
            "- Information – factual reporting or sharing news without strong opinion\n"
            "- Commentary – personal views or commentary not tied to marketing or scams\n"
            "- Entertainment – movies, music, celebrities, memes, humor\n"
            "- Technology – tech products, software, AI, gadgets\n"
            "- Personal – everyday experiences or personal updates\n"
            "- Other – does not clearly fit any category above\n"
            "\n"
            "Instructions:\n"
            "- Consider hashtags, emojis, slang, shortened links, and informal language.\n"
            "- Focus on the primary intent of the post.\n"
            "- If multiple categories apply, select the most dominant one.\n"
            "- Do not assume legitimacy; classify based only on text signals.\n"
            "- Output only the category name and nothing else.\n"
            "- If the post contains the exact phrase \"Airdrop Now Available\", classify it as Scam\n"
            "- Do NOT classify a post as Scam  if it is clearly warning, advising, or cautioning users about scams (e.g., \"be careful\", \"do not click\", \"avoid links\", \"this is a scam\").\n"
            "\n"
            "Post:\n"
            "\"" + body+ "\""
        )
        logging.debug(prompt)
        try:
            response = ollama.chat(
                model=model_name,
                messages=[{
                    "role": "user",
                    "content": prompt
                }],
                format="json",
                options={
                    "temperature": 0,
                    "format": "json"
                }
            )

            data = json.loads(response["message"]["content"])
            logging.info(f"LLM Response Data: {data}")
            

            return data["category"] if "category" in data else ""

        except Exception:
            # absolute fallback
            logging.error(response["message"]["content"])
            return "No"
    else:
        return "No"

def extract_image_from_video_advance(url):
    try:
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

        logging.debug("Saved " + filename)
        
        driver.quit()
        return filename
    except Exception as e:
        logging.error(f"Error extracting image from video: {e}")
        return None
    
def grab_frame_opencv(video_url):
    try:
        logging.debug("Using OpenCV")
        cap = cv2.VideoCapture(video_url)
        cap.set(cv2.CAP_PROP_POS_MSEC, 1000)  # 1s

        ret, frame = cap.read()
        cap.release()

        if not ret:
            raise RuntimeError("Failed to read frame from video")
        filename = "video_frame.jpg"
        cv2.imwrite(filename, frame)
        logging.debug("Saved:", filename)
        return filename
    except Exception as e:
        logging.error(f"Error grabbing frame with OpenCV: {e}")
        return None

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
    logging.debug(now)
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
        logging.info("Checked notifications done.")

       
def clean_text(text):
    return "".join(
        c for c in text
        if c.isprintable() or c in "\n\t"
    )

def is_html(url):
    try:
        r = requests.head(url, allow_redirects=True, timeout=10)
        content_type = r.headers.get("Content-Type", "")
        return "text/html" in content_type
    except:
        return False
def is_gif(path):
    with open(path, "rb") as f:
        header = f.read(6)
    return header in (b"GIF87a", b"GIF89a")

def is_gif_by_extension(url):
    return urlparse(url).path.lower().endswith(".gif")

TXID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")

def is_arweave_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and parsed.netloc.endswith("arweave.net")

def extract_arweave_txid(url: str):
    """
    Returns txid ONLY if the URL is confirmed to be Arweave.
    Otherwise returns None.
    """
    if not is_arweave_url(url):
        return None

    parsed = urlparse(url)
    path = parsed.path.lstrip("/")

    # Must have a path
    if not path:
        return None

    txid = path.split("/")[0]

    # Validate txid format
    if TXID_PATTERN.fullmatch(txid):
        return txid

    return None
def run():
    global notify_user_list,post_id_list,process_videos

    max_nano_ts=0
    last_nano_tx=0
    nano_ts=0
    post_id_list_feed=[]
  
    posts_count=0
    last_run_report = datetime.datetime.now()# - datetime.timedelta(hours=12)
    stats_video={}
    stats={}
    last_post=""
    crashes_count=0
    post = None
    spam_list=[]
    while(True):
        try:
            if result:=load_from_json("spam_list.json"):
                spam_list=result
            

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
                logging.debug(f'Last Post Hash:{last_post["PostHashHex"] if last_post!="" else "First run, no last post"}' )
                if results:=get_posts_stateless(bot_public_key,NumToFetch=250,PostHashHex=last_post["PostHashHex"] if last_post!="" else ""):
                     
                    for post in results["PostsFound"]:
                        
                        last_post = post
                        if "TimestampNanos" in post:
                            logging.debug( f'Timestamp:{post["TimestampNanos"]}' )
                            nano_ts=post["TimestampNanos"]
                        else:
                            logging.debug("No TimestampNanos in post")
                            continue
                        if nano_ts > max_nano_ts:
                            max_nano_ts = nano_ts
                        if nano_ts<=last_nano_tx:
                            logging.debug("Old feed")
                            #break   #comment this line to process old posts when going back the feed
                        if post["PostHashHex"] not in post_id_list_feed:
                            ts=nano_ts/1e9
                            dt=datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                            
                            
                            posts_count+=1
                            post_username=None
                            if "ProfileEntryResponse" in post:
                               if post['ProfileEntryResponse'] is not None:
                                   if "Username" in post['ProfileEntryResponse']:
                                       if post['ProfileEntryResponse']['Username'] is not None:
                                            post_username=post['ProfileEntryResponse']['Username']
                            if post_username is None:
                                if post["PostHashHex"] not in post_id_list_feed:
                                    post_id_list_feed.append(post["PostHashHex"])
                                    save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                    logging.info("Skipping post with no username.")
                                continue
                            post_body = unicodedata.normalize("NFKC", post["Body"])
                            post_body = post_body[:500] + "..." if len(post_body) > 500 else post_body
                            post_body=clean_text(post_body)
                            logging.info(f"\n---- New Post #{posts_count} ----")
                            logging.info(f"Post Hash:{post['PostHashHex']}")
                            logging.debug(f"UTC Time:{dt}")
                            logging.info(f"Username:{post_username}")
                            logging.info(f'PublicKeyBase58Check:{post['ProfileEntryResponse']["PublicKeyBase58Check"]}')
                            logging.info("=============Body==============")
                            logging.info(post_body)
                            logging.info("===============END=============")
                            
                            if post['ProfileEntryResponse']["PublicKeyBase58Check"] == bot_public_key:
                                logging.info("Skipping own post.")
                                if post["PostHashHex"] not in post_id_list_feed:
                                    post_id_list_feed.append(post["PostHashHex"])
                                    save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                continue

                            if post_username in SCAM_USERS:
                                logging.info("Skipping post from known scam user.")
                                if post["PostHashHex"] not in post_id_list_feed:
                                    post_id_list_feed.append(post["PostHashHex"])
                                    save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                continue

                            result = get_post_associations(post["PostHashHex"],"TOPIC","Scam")
                            if len(result["Associations"])>0:
                                logging.info("Skipping post already marked as Scam.")
                                for assoc in result["Associations"]:
                                    logging.info(f"AssociationID:{assoc}")
                                if post["PostHashHex"] not in post_id_list_feed:
                                    post_id_list_feed.append(post["PostHashHex"])
                                    save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                continue
                            result = post_associations_counts(post["PostHashHex"],"TOPIC",[])
                            if result["Total"]>0:
                                logging.info("Skipping post already categorized.")
                                if post["PostHashHex"] not in post_id_list_feed:
                                    post_id_list_feed.append(post["PostHashHex"])
                                    save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                continue

                            text_type=""
                            if post_body!="":
                                text_type = text_category(post_body)
                                logging.info(f"Text category: {text_type}")
                                
                            if text_type!="":
                                create_post_associations(bot_public_key,post["PostHashHex"],"TOPIC",text_type)
                            
                            if text_type=="Scam":
                                logging.info("Skipping scam post.")
                                if post['ProfileEntryResponse']["PublicKeyBase58Check"] not in spam_list:
                                    spam_list.append(post['ProfileEntryResponse']["PublicKeyBase58Check"])
                                    save_to_json(spam_list,"spam_list.json")
                                post_id_list_feed.append(post["PostHashHex"])
                                save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                continue

                            if process_videos==True:
                                if post["VideoURLs"]!=None and len(post["VideoURLs"])>0:
                                    video_url=post["VideoURLs"][0]
                                    logging.info(f"Video URL:{video_url}")
                                    if video_url!="":
                                        image_file_name=None
                                        retry_count=0
                                        if is_html(video_url):
                                            logging.info("Video URL is HTML")
                                            while image_file_name is None and retry_count<=2:
                                                image_file_name= extract_image_from_video_advance(video_url)
                                                if image_file_name is None:
                                                    retry_count+=1
                                                    time.sleep(5)
                                                    if retry_count>2:
                                                        logging.info("Skipping video post after 3 failed attempts.")
                                                        logging.info("Failed to extract middle frame from video. Skipping post.")
                                        else:
                                            logging.info("Video URL is not HTML")
                                            while image_file_name is None and retry_count<=2:
                                                image_file_name= grab_frame_opencv(video_url)
                                                if image_file_name is None:
                                                    retry_count+=1
                                                    time.sleep(5)
                                                    if retry_count>2:
                                                        logging.error("Skipping video post after 3 failed attempts.")
                                                        logging.error("Failed to extract middle frame from video. Skipping post.")

                                        post_id_list_feed.append(post["PostHashHex"])
                                        save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                        if image_file_name is None:
                                            logging.error("Skipping post due to failed video extraction.")
                                            continue
                                        logging.info(f"Extracted image file from video: {image_file_name}")     
                                        
                                        category,sub = categorize_image_with_confidence(image_file_name,post_body)

                                        if stats_calculate ==True:
                                            if category!="":
                                                stats_video[category]=stats_video.get(category,0)+1
                                            if(category != sub):
                                                if sub!="":
                                                    stats_video[sub]=stats_video.get(sub,0)+1

                                        save_to_json(stats_video,"stats_video.json")

                                        logging.info(f"category: {category},Sub category: {sub}")


                                        tags = {category, sub}  # set removes duplicates
                                        reply_body = "categories: " + " ".join(f"#{t}" for t in tags if t)
                                        #create_post(reply_body,post["PostHashHex"],[category,sub])
                                        if category=="nature" or sub=="nature":
                                            create_quote_post(reply_body,post["PostHashHex"],[category,sub])
                                        if category!="":
                                            create_post_associations(bot_public_key,post["PostHashHex"],"TOPIC",category)
                                        if sub!="":
                                            if category != sub:
                                                create_post_associations(bot_public_key,post["PostHashHex"],"TOPIC",sub)
                                        #result = post_associations_counts(post["PostHashHex"],"TOPIC",ALLOWED)
                                        #logging.info(f"Post associations counts: {result}")
                                        users_list=[]
                                        users_list = list(
                                            set(notify_user_list.get("video", {}).get(category, [])) |
                                            set(notify_user_list.get("video", {}).get(sub, []))
                                        )

                                        usernames_str=""
                                        for user_public_key in users_list:
                                            user = get_single_profile("",user_public_key)
                                            if user != None and "Profile" in user:
                                                if "Username" in user["Profile"]:
                                                    if user["Profile"]["Username"] != None:
                                                        if post['ProfileEntryResponse']["PublicKeyBase58Check"]!=user_public_key:
                                                                usernames_str += "@"+user["Profile"]["Username"]+" "  
                                        if usernames_str!="":
                                            if global_notify==True:
                                                create_post(f"{usernames_str} Check out this interesting video post by {post_username}, categories: {category}, {sub}",post["PostHashHex"])        
                                        logging.debug(stats_video)
                                        
                                        logging.info("==============================")
                            if process_images==True:
                                if post["ImageURLs"]!=None and len(post["ImageURLs"])>0:
                                    image_url=post["ImageURLs"][0]
                                    logging.info(f"Image URL:{image_url}")

                                    if is_gif_by_extension(image_url):
                                        logging.info("Image is GIF")
                                        if(post["PostHashHex"] not in post_id_list_feed):
                                            post_id_list_feed.append(post["PostHashHex"])
                                            save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                        continue

                                    if is_arweave_url(image_url):
                                        arweave_txid = extract_arweave_txid(image_url)
                                        if arweave_txid:
                                            image_url = f"https://arweave.net/{arweave_txid}"
                                            logging.info(f"Extracted Arweave URL: {image_url}")
                                        else:
                                            logging.info("Invalid Arweave URL.")
                                            if(post["PostHashHex"] not in post_id_list_feed):
                                                post_id_list_feed.append(post["PostHashHex"])
                                                save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                            continue
                                    image_file_name= extract_image_url(image_url)
                                    logging.debug(image_file_name)
                                    image_save_path = img_path / image_file_name

                                    if not image_save_path.exists():
                                        logging.info("Image not found locally. Downloading...")
                                        image_data = requests.get(image_url).content
                                        with open(image_save_path, 'wb') as handler:
                                            handler.write(image_data)
                                    else:
                                        logging.info("Image already exists. Skipping download.") 

                                    if(is_gif(image_save_path)):
                                        logging.info("Image is GIF")
                                        if(post["PostHashHex"] not in post_id_list_feed):
                                            post_id_list_feed.append(post["PostHashHex"])
                                            save_to_json(post_id_list_feed,"postIdList_LIKE.json")
                                        continue                             

                                    category,sub = categorize_image_with_confidence(image_save_path,post_body)

                                    if(post["PostHashHex"] not in post_id_list_feed):
                                        post_id_list_feed.append(post["PostHashHex"])
                                        save_to_json(post_id_list_feed,"postIdList_LIKE.json")

                                    if stats_calculate ==True:
                                        if category!="":
                                            stats[category]=stats.get(category,0)+1
                                        if(category != sub):
                                            if sub!="":
                                                stats[sub]=stats.get(sub,0)+1

                                    save_to_json(stats,"stats.json")
                                    logging.info(f"category: {category},Sub category: {sub}")

                                    
                                    tags = {category, sub}  # set removes duplicates
                                    reply_body = "categories: " + " ".join(f"#{t}" for t in tags if t)
                                    #create_post(reply_body,post["PostHashHex"],[category,sub])
                                    if category=="nature" or sub=="nature":
                                        create_quote_post(reply_body,post["PostHashHex"],[category,sub])
                                    if category!="":
                                        create_post_associations(bot_public_key,post["PostHashHex"],"TOPIC",category)
                                    if sub!="":
                                        if category != sub:
                                            create_post_associations(bot_public_key,post["PostHashHex"],"TOPIC",sub)
                                    result = post_associations_counts(post["PostHashHex"],"TOPIC",ALLOWED)
                                    logging.info(f"Post associations counts: {result}")
                                    users_list=[]
                                    users_list = list(
                                        set(notify_user_list.get("image", {}).get(category, [])) |
                                        set(notify_user_list.get("image", {}).get(sub, []))
                                    )

                                    usernames_str=""

                                    for user_public_key in users_list:
                                        user = get_single_profile("",user_public_key)
                                        if user != None and "Profile" in user:
                                            if "Username" in user["Profile"]:
                                                if user["Profile"]["Username"] != None:
                                                    if post['ProfileEntryResponse']["PublicKeyBase58Check"]!=user_public_key:
                                                        usernames_str += "@"+user["Profile"]["Username"]+" "  
                                    if usernames_str!="":
                                        if global_notify==True:
                                            create_post(f"{usernames_str} Check out this interesting image post by {post_username}, categories: {category}, {sub}",post["PostHashHex"])      

                                    logging.debug(stats)
                                    
                                    logging.info("==============================")

                            if(post["PostHashHex"] not in post_id_list_feed):
                                post_id_list_feed.append(post["PostHashHex"])
                                save_to_json(post_id_list_feed,"postIdList_LIKE.json")
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
                logging.debug(info_body)
    
                now = datetime.datetime.now()
    
                if now - last_run_report >= datetime.timedelta(hours=3) and posts_count>100:
                    print(info_body)
                    create_post(info_body,"")
                    last_run_report = now
                    posts_count=0

                time.sleep(update_time_interval)
        except Exception as e:
            crashes_count+=1
            logging.error(f"Crash count: {crashes_count}")
            if crashes_count>=5:
                logging.error("Too many crashes, exiting.")
                break
                
            logging.error(e)
            time.sleep(1)

run()
