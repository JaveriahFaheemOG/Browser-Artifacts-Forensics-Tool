from ctypes import CDLL, Structure, c_int, c_uint, c_void_p, c_char_p, c_ubyte, cast, byref, string_at
import sys
import os
import winreg
import glob
import base64
import time
import getopt
import getpass
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import os
import shutil
import datetime



# Functions for Chromium-based browsers (Code1)-------------------------------------------------------------------------------
BRAVE_USER_DATA_PATH = os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data")
BRAVE_LOCAL_STATE = os.path.join(BRAVE_USER_DATA_PATH, "Local State")

def hex_viewer(file_path, num_bytes=512):
    """
    Reads and displays the hex representation of a file's binary data.
    :param file_path: Path to the file to be viewed.
    :param num_bytes: Number of bytes to read and display (default: 512 bytes).
    """
    try:
        with open(file_path, "rb") as file:
            print(f"\nHex View of {file_path}:")
            print("-" * 50)
            chunk = file.read(num_bytes)  # Read a specific number of bytes
            ascii_data = "".join([chr(b) if 32 <= b < 127 else '.' for b in chunk])

            for i in range(0, len(chunk), 16):  # Process 16 bytes per line
                line = chunk[i:i+16]
                hex_pairs = " ".join([f"{byte:02X}" for byte in line])  # Format hex bytes in pairs
                ascii_line = "".join([chr(byte) if 32 <= byte < 127 else '.' for byte in line])
                
                print(f"{hex_pairs:<48} {ascii_line}")
            print("-" * 50)
    except PermissionError:
        print(f"❌ Permission denied: {file_path}. Try closing Brave or running as Administrator.")
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
    except Exception as e:
        print(f"❌ Error reading file: {e}")

def get_decryption_key(local_state_path):
    """ Get decryption key for Brave and Chromium-based browsers """
    with open(local_state_path, "r", encoding="utf-8") as file:
        local_state = json.load(file)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return key

def decrypt_password(password, key):
    """ Decrypt password using AES key """
    try:
        iv = password[3:15]
        payload = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)[:-16].decode()
        return decrypted_pass
    except Exception as e:
        return f"Error decrypting password: {e}"


# Fetch and Decrypt Brave Passwords
def fetch_brave_passwords(login_data_path, key):
    """
    Fetch and decrypt saved passwords from Brave's Login Data database.
    :param login_data_path: Path to Brave's Login Data file.
    :param key: AES decryption key.
    :return: List of tuples (origin_url, username, decrypted_password).
    """
    LOGIN_DATA_COPY = "LoginData_Copy.db"

    try:
        shutil.copyfile(login_data_path, LOGIN_DATA_COPY)

        conn = sqlite3.connect(LOGIN_DATA_COPY)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

        passwords = []
        for origin_url, username, password in cursor.fetchall():
            decrypted_password = decrypt_password(password, key)
            passwords.append((origin_url, username, decrypted_password))

        conn.close()
        os.remove(LOGIN_DATA_COPY)
        return passwords
    except Exception as e:
        print(f"Error fetching passwords: {e}")
        if os.path.exists(LOGIN_DATA_COPY):
            os.remove(LOGIN_DATA_COPY)
        return []

def fetch_brave_bookmarks(profile_path):
    """
    Fetch and display bookmarks from Brave, with an option for hex view.
    :param profile_path: Path to the Brave browser profile directory.
    """
    bookmarks_path = os.path.join(profile_path, "Bookmarks")

    try:
        # Check if the Bookmarks file exists
        if not os.path.exists(bookmarks_path):
            print("❌ Bookmarks file not found.")
            return

        # Offer hex viewing for the bookmarks file
        print("\n📂 Brave Bookmarks File Found!")
        view_hex = input("Would you like to view the bookmarks file in hex? (y/n): ").strip().lower()
        if view_hex == 'y':
            hex_viewer(bookmarks_path)

        # Read and parse the bookmarks JSON file
        with open(bookmarks_path, "r", encoding="utf-8") as file:
            bookmarks = json.load(file)

        # Extract relevant details from bookmarks
        bookmark_data = []
        for folder in bookmarks.get("roots", {}).values():
            for item in folder.get("children", []):
                if 'name' in item and 'type' in item and item['type'] == 'url':
                    bookmark_data.append({
                        "name": item['name'],
                        "type": item['type'],
                        "url": item.get('url', 'No URL')
                    })

        # Display bookmarks interactively
        if bookmark_data:
            print("\n🗂️ Bookmarks:")
            for idx, bookmark in enumerate(bookmark_data, start=1):
                print(f"{idx}. {bookmark['name']} ({bookmark['type']}): {bookmark['url']}")
                
        else:
            print("No bookmarks found.")

    except json.JSONDecodeError:
        print("❌ Error decoding bookmarks JSON file. It may be corrupted.")
    except PermissionError:
        print(f"❌ Permission denied: {bookmarks_path}. Try closing Brave or running as Administrator.")
    except Exception as e:
        print(f"❌ Error reading bookmarks: {e}")

def fetch_brave_history(profile_path):
    """
    Fetch browsing history from Brave and display it with an option for hex view.
    :param profile_path: Path to the Brave browser profile directory.
    """
    history_path = os.path.join(profile_path, "History")
    HISTORY_COPY = "History_Copy.db"

    try:
        # Check if the History file exists
        if not os.path.exists(history_path):
            print("❌ History file not found.")
            return

        # Offer hex viewing for the history file
        print("\n📂 Brave History File Found!")
        view_hex = input("Would you like to view the history file in hex? (y/n): ").strip().lower()
        if view_hex == 'y':
            hex_viewer(history_path)

        # Copy the database file to avoid locks and permissions issues
        shutil.copyfile(history_path, HISTORY_COPY)

        # Connect to the copied database
        conn = sqlite3.connect(HISTORY_COPY)
        cursor = conn.cursor()

        # Check for free pages (residual/deleted data)
        cursor.execute("PRAGMA freelist_count;")
        free_pages = cursor.fetchone()[0]
        print(f"🔍 Free pages detected in the database: {free_pages}")
        if free_pages > 0:
            print("⚠️ Residual data may exist. Use a forensic tool to recover deleted entries.")

        # Fetch URL, title, and last visit time
        cursor.execute("SELECT url, title, last_visit_time FROM urls")
        history = cursor.fetchall()

        # Close the database connection
        conn.close()
        os.remove(HISTORY_COPY)

        # Convert last_visit_time to a human-readable format
        formatted_history = []
        for url, title, last_visit_time in history:
            # Convert last_visit_time from microseconds since epoch to a human-readable format
            try:
                visit_time_seconds = last_visit_time / 1000000 - 11644473600  # Adjust for Windows FILETIME epoch
                last_visited = datetime.datetime.fromtimestamp(visit_time_seconds, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')
            except Exception as e:
                last_visited = f"Error converting time: {e}"

            formatted_history.append((url, title, last_visited))

        # Display the history interactively
        if formatted_history:
            print("\n📜 Browsing History:")
            print(f"{'URL':<60} {'Title':<30} {'Last Visit Time':<20}")
            print("-" * 110)
            for url, title, last_visited in formatted_history:
                print(f"{url[:58]:<60} {title[:28]:<30} {last_visited:<20}")
        else:
            print("No browsing history found.")

    except sqlite3.OperationalError as e:
        print(f"❌ Error accessing database: {e}. Make sure Brave is closed.")
    except PermissionError:
        print(f"❌ Permission denied: {history_path}. Try closing Brave or running as Administrator.")
    except Exception as e:
        print(f"❌ Error reading history: {e}")
    finally:
        if os.path.exists(HISTORY_COPY):
            os.remove(HISTORY_COPY)

def fetch_brave_cache(profile_path):
    """
    Fetch and display cache files from Brave browser profile with an option for hex view.
    :param profile_path: Path to the Brave browser profile directory.
    """
    cache_path = os.path.join(profile_path, "Cache")
    cache_files = []
    
    # Walk through the cache directory and collect files
    for root, dirs, files in os.walk(cache_path):
        for file in files:
            cache_files.append(os.path.join(root, file))
    
    if cache_files:
        print("\n🗂️ Cache Files Found:")
        for idx, cache_file in enumerate(cache_files, start=1):
            print(f"{idx}. {cache_file}")
        
        # User chooses a file to view in hex
        try:
            file_choice = int(input("\nEnter the file number to view in hex (or 0 to skip): "))
            if file_choice > 0 and file_choice <= len(cache_files):
                hex_viewer(cache_files[file_choice - 1])
            else:
                print("No file selected for hex view.")
        except ValueError:
            print("Invalid input. Skipping hex view.")
    else:
        print("No cache files found.")
    return cache_files

def fetch_brave_downloads(profile_path):
    """
    Fetch the list of downloaded files from Brave's History database.
    :param profile_path: Path to Brave's browser profile directory.
    :return: List of dictionaries containing download details.
    """
    history_path = os.path.join(profile_path, "History")
    HISTORY_COPY = "History_Copy.db"

    try:
        # Check if the History file exists
        if not os.path.exists(history_path):
            print("❌ History file not found.")
            return []

        # Make a copy of the History file to avoid locks
        shutil.copyfile(history_path, HISTORY_COPY)

        # Connect to the copied History SQLite database
        conn = sqlite3.connect(HISTORY_COPY)
        cursor = conn.cursor()

        # Query the downloads table
        cursor.execute("""
            SELECT 
                target_path, 
                current_path, 
                total_bytes, 
                start_time, 
                end_time, 
                received_bytes 
            FROM downloads
        """)

        downloads = []
        for row in cursor.fetchall():
            target_path, current_path, total_bytes, start_time, end_time, received_bytes = row
            
            # Convert timestamps to human-readable format
            def format_time(time):
                try:
                    # Convert from microseconds since Windows epoch (1601-01-01)
                    seconds = time / 1000000 - 11644473600
                    return datetime.datetime.fromtimestamp(seconds).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    return "Invalid Timestamp"

            downloads.append({
                "target_path": target_path,
                "current_path": current_path,
                "total_bytes": total_bytes,
                "received_bytes": received_bytes,
                "start_time": format_time(start_time),
                "end_time": format_time(end_time)
            })

        # Close the database connection and remove the copied file
        conn.close()
        os.remove(HISTORY_COPY)

        # Print and return download details
        if downloads:
            print("\n📥 Downloads Found:")
            for idx, download in enumerate(downloads, start=1):
                print(f"{idx}. File: {download['target_path']}")
                print(f"   Current Path: {download['current_path']}")
                print(f"   Total Size: {download['total_bytes']} bytes")
                print(f"   Received: {download['received_bytes']} bytes")
                print(f"   Start Time: {download['start_time']}")
                print(f"   End Time: {download['end_time']}\n")
        else:
            print("No downloads found.")

        return downloads

    except sqlite3.OperationalError as e:
        print(f"❌ Error accessing database: {e}. Make sure Brave is closed.")
    except PermissionError:
        print(f"❌ Permission denied: {history_path}. Try closing Brave or running as Administrator.")
    except Exception as e:
        print(f"❌ Error reading downloads: {e}")
    finally:
        if os.path.exists(HISTORY_COPY):
            os.remove(HISTORY_COPY)

def fetch_brave_extensions_with_hex(user_path):
    """
    Fetch and display installed extensions for the Brave browser, with an option to view manifest.json in hex.
    
    Parameters:
        user_path (str): Path to the Brave user data directory.
    
    Output:
        Prints the list of installed extensions along with their names and descriptions.
        Optionally, allows the user to view the manifest.json file in hex format.
    """
    extensions_dir = os.path.join(user_path, "Extensions")
    
    if os.path.exists(extensions_dir):
        print("\n🔍 Installed Brave Extensions:")
        print(f"{'Extension Name':<40} {'Version':<15} {'Description':<50}")
        print("-" * 110)

        extensions = []  # List to store manifest file paths for hex view
        for ext_id in os.listdir(extensions_dir):
            ext_path = os.path.join(extensions_dir, ext_id)
            if os.path.isdir(ext_path):
                # Search for manifest.json in nested version folders
                for root, dirs, files in os.walk(ext_path):
                    if "manifest.json" in files:
                        manifest_path = os.path.join(root, "manifest.json")
                        try:
                            with open(manifest_path, "r", encoding="utf-8") as manifest_file:
                                manifest_data = json.load(manifest_file)
                                name = manifest_data.get("name", "Unknown")
                                version = manifest_data.get("version", "Unknown")
                                description = manifest_data.get("description", "No description available")
                                extensions.append((name, manifest_path))  # Save for hex view
                                print(f"{name[:38]:<40} {version:<15} {description[:48]:<50}")
                        except Exception as e:
                            print(f"❌ Could not read manifest.json for {ext_id}: {e}")
                        break  # Stop after finding the first valid manifest.json

        # Option for hex view of a manifest.json file
        try:
            if extensions:
                print("\nAvailable extensions for hex view:")
                for i, (name, _) in enumerate(extensions, 1):
                    print(f"{i}. {name}")
                choice = int(input("\nEnter the number of the extension to view its manifest.json in hex (or 0 to skip): "))
                if 0 < choice <= len(extensions):
                    _, manifest_path = extensions[choice - 1]
                    hex_viewer(manifest_path)
                else:
                    print("No file selected for hex view.")
            else:
                print("No extensions found for hex view.")
        except ValueError:
            print("Invalid input. Skipping hex view.")
    else:
        print("❌ Extensions directory not found. Make sure you provided the correct Brave user data path.")

def get_installation_date_from_registry(software_name):
    """ Retrieve the installation date of a specific software from the Windows Registry """
    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    for reg_path in reg_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    sub_key_name = winreg.EnumKey(key, i)
                    sub_key_path = f"{reg_path}\\{sub_key_name}"
                    
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_key_path) as sub_key:
                        try:
                            display_name = winreg.QueryValueEx(sub_key, "DisplayName")[0]
                            if display_name == software_name:
                                install_date = winreg.QueryValueEx(sub_key, "InstallDate")[0]
                                return install_date
                        except FileNotFoundError:
                            continue
        except FileNotFoundError:
            continue
    
    return None

def list_profiles(user_data_path):
    """ List all user profiles in the Brave user data directory """
    profiles = [f for f in os.listdir(user_data_path) if f.startswith('Profile ') or f == 'Default']
    return profiles

# Functions for Non-Chromium based browsers (Code2)---------------------------------------------------------------------------------------------
# Password structures
class SECItem(Structure):
    _fields_ = [('type', c_uint), ('data', c_void_p), ('len', c_uint)]


class secuPWData(Structure):
    _fields_ = [('source', c_ubyte), ('data', c_char_p)]


# Error codes and password types
(SECWouldBlock, SECFailure, SECSuccess) = (-2, -1, 0)
(PW_NONE, PW_FROMFILE, PW_PLAINTEXT, PW_EXTERNAL) = (0, 1, 2, 3)


def findpath_userdirs(browser_type):
    appdata = os.getenv('APPDATA')  # Use APPDATA for Windows
    if browser_type == 'librewolf':
        usersdir = os.path.join(appdata, 'librewolf', 'Profiles')
    else:
        usersdir = os.path.join(appdata, 'Mozilla', 'Firefox', 'Profiles')

    res = []
    if os.path.isdir(usersdir):
        for user in os.listdir(usersdir):
            if os.path.isdir(os.path.join(usersdir, user)):
                res.append(os.path.join(usersdir, user))
    return res


def errorlog(row, path, libnss):
    print("\n❌ ----[Error Decoding] Writing `error.log`")
    print(f"🔍 Error Code: {libnss.PORT_GetError()}")
    try:
        with open('error.log', 'a') as f:
            f.write("-------------------\n")
            f.write(f"📂 #ERROR in: {path} at {time.ctime()}\n")
            f.write(f"🌐 Site: {row['hostname']}\n")
            f.write(f"👤 Username: {row['encryptedUsername']}\n")
            f.write(f"🔒 Password: {row['encryptedPassword']}\n")
            f.write("-------------------\n")
    except IOError:
        print("⚠️ Error while writing logfile - No log created!")


class JSONLogins(object):
    def __init__(self, dbpath):
        import json
        with open(dbpath) as fh:
            try:
                self._data = json.load(fh)
            except Exception as Error:
                raise RuntimeError(f"❌ Failed to read {dbpath} ({Error})")

    def __iter__(self):
        return iter(self._data['logins'])


class SQLiteLogins(object):
    def __init__(self, dbpath):
        import sqlite3
        self._conn = sqlite3.connect(dbpath)
        self._cur = self._conn.cursor()
        self._cur.execute('SELECT * FROM moz_logins;')

    def __iter__(self):
        for row in self._cur:
            yield {
                'hostname': row[1],
                'encryptedUsername': row[6],
                'encryptedPassword': row[7],
                'timeCreated': row[10],
                'timeLastUsed': row[11],
                'timePasswordChanged': row[12]
            }


def decrypt(val, libnss, pwdata):
    try:
        item_bytes = base64.b64decode(val)
    except TypeError as msg:
        print(f"⚠️ --TypeError ({msg}) Value: ({val})")
        return None

    item_sec = SECItem()
    item_clr = SECItem()

    item_sec.data = cast(c_char_p(item_bytes), c_void_p)
    item_sec.len = len(item_bytes)

    if libnss.PK11SDR_Decrypt(byref(item_sec), byref(item_clr), byref(pwdata)) == -1:
        return None
    else:
        return string_at(item_clr.data, item_clr.len).decode('utf-8')

 
#Add an option to view the database file in hex format before parsing it:
def readsignonDB(userpath, dbname, pw, libnss):
    print(f"\n📂 Database: {dbname}")
    dbpath = os.path.join(userpath, dbname)
    
    # Offer hex view
    view_hex = input(f"Would you like to view {dbname} in hex? (y/n): ").strip().lower()
    if view_hex == 'y':
        hex_viewer(dbpath)
    
    # Continue processing the database as before
    keySlot = libnss.PK11_GetInternalKeySlot()
    libnss.PK11_CheckUserPassword(keySlot, pw.encode('utf-8'))
    libnss.PK11_Authenticate(keySlot, True, 0)

    pwdata = secuPWData()
    pwdata.source = PW_NONE
    pwdata.data = None

    ext = dbname.split('.')[-1]
    db = SQLiteLogins(dbpath) if ext == 'sqlite' else JSONLogins(dbpath)

    for rec in db:
        print(f"🌐 --Site: {rec['hostname']}")
        for item in ['Username', 'Password']:
            clr = decrypt(rec[f'encrypted{item}'], libnss, pwdata)
            if clr is None:
                errorlog(rec, dbpath, libnss)
            else:
                print(f"----{item}: {clr}")


#i added hex view option for the places.sqlite database here
def readHistory(userpath):
    import sqlite3
    history_db = os.path.join(userpath, 'places.sqlite')
    if os.path.exists(history_db):
        # Offer hex view
        view_hex = input("Would you like to view the history database in hex? (y/n): ").strip().lower()
        if view_hex == 'y':
            hex_viewer(history_db)

        # Continue reading history
        print("\n📜 Browsing History:")
        conn = sqlite3.connect(history_db)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, visit_date FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id")
        for row in cursor.fetchall():
            url, title, visit_date = row
            visit_time = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(visit_date / 1000000)) if visit_date else "Not available"
            print(f"🌐 --URL: {url}\n📄 ----Title: {title}\n🕒 ----Visited On: {visit_time}")
        conn.close()
    else:
        print("No browsing history found.")


#added hex view for bm's database
def readBookmarks(userpath):
    import sqlite3
    bookmarks_db = os.path.join(userpath, 'places.sqlite')
    if os.path.exists(bookmarks_db):
        # Offer hex view
        view_hex = input("Would you like to view the bookmarks database in hex? (y/n): ").strip().lower()
        if view_hex == 'y':
            hex_viewer(bookmarks_db)

        # Continue reading bookmarks
        print("\n🔖 Bookmarks:")
        conn = sqlite3.connect(bookmarks_db)
        cursor = conn.cursor()
        cursor.execute("SELECT moz_places.url, moz_bookmarks.title FROM moz_bookmarks "
                       "JOIN moz_places ON moz_bookmarks.fk = moz_places.id")
        for row in cursor.fetchall():
            url, title = row
            print(f"📄 --Title: {title}\n🌐 ----URL: {url}")
        conn.close()
    else:
        print("No bookmarks found.")


def printCacheData(userpath):
    """
    Fetch and view cache data for Firefox/LibreWolf.
    Debugs and provides detailed information if no cache is found.
    """
    cache_dir = os.path.join(userpath, 'cache2')
    if os.path.exists(cache_dir):
        print(f"\n📂 Cache directory found: {cache_dir}")
        print("\n🗂️ Listing cache files:")
        for root, dirs, files in os.walk(cache_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                print(f"📦 Cache file: {file} ({file_size} bytes)")
                
                # Ask user if they want to view the file in hex
                view_hex = input(f"Would you like to view the file {file} in hex? (y/n): ").strip().lower()
                if view_hex == 'y':
                    hex_viewer(file_path)  # Call the hex viewer function (assumed already implemented)
    else:
        print(f"❌ No cache directory found under: {cache_dir}")
        print("➡️ Ensure the profile path is correct and disk-based caching is enabled in the browser.")



#downloads fetching
def readDownloads(userpath):
    """
    Fetch and display download history from non-Chromium browsers.
    Includes an option to view the database in hex format.
    """
    places_db = os.path.join(userpath, 'places.sqlite')
    
    if os.path.exists(places_db):
        # Offer hex view
        view_hex = input("Would you like to view the places.sqlite database in hex? (y/n): ").strip().lower()
        if view_hex == 'y':
            hex_viewer(places_db)

        print("\n📥 Firefox Downloads:")
        conn = sqlite3.connect(places_db)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    moz_places.url AS source_url,
                    moz_places.title AS file_name,
                    datetime(moz_historyvisits.visit_date/1000000, 'unixepoch', 'localtime') AS download_time
                FROM moz_places
                JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
                WHERE moz_places.url LIKE '%.%';
            """)

            downloads = cursor.fetchall()
            if downloads:
                print(f"{'File Name':<40} {'Source URL':<60} {'Download Time':<20}")
                print("-" * 130)
                for i, download in enumerate(downloads, start=1):
                    file_name = download[1] or "Unknown"
                    source_url = download[0] or "Unknown"
                    download_time = download[2] or "Unknown"

                    print(f"{file_name[:38]:<40} {source_url[:58]:<60} {download_time:<20}")

                # URL handling for hex view
                try:
                    file_choice = int(input("\nEnter the number of the download to view in hex (or 0 to skip): "))
                    if file_choice > 0 and file_choice <= len(downloads):
                        selected_url = downloads[file_choice - 1][0]
                        print(f"🔗 Selected URL: {selected_url}")
                        print("Cannot view this URL in hex because it is not a local file.")
                    else:
                        print("No file selected.")
                except ValueError:
                    print("Invalid input. Skipping.")
            else:
                print("No downloads found.")
        except sqlite3.Error as e:
            print(f"❌ Error querying places.sqlite: {e}")
        finally:
            conn.close()
    else:
        print("❌ places.sqlite database not found.")
      
        
def get_installation_time(browser_type):
    if browser_type == 'librewolf':
        install_dir = r"C:\Program Files\LibreWolf"
    else:
        install_dir = r"C:\Program Files\Mozilla Firefox"

    if os.path.exists(install_dir):
        install_time = os.path.getctime(install_dir)
        return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(install_time))
    return "Installation time not found"


class LibNSS(object):
    def __init__(self, libnss, userpath):
        self._libnss = libnss
        init_result = self._libnss.NSS_Init(userpath.encode('utf-8'))
        if init_result != 0:
            error_msg = self._libnss.PORT_GetError()
            raise RuntimeError(f"❌ libnss init error: {init_result} - {error_msg}")
        else:
            print("✔ libnss initialized successfully")

    def __enter__(self):
        return self

    def __exit__(self, ExcType, ExcVal, ExcTb):
        self._libnss.NSS_Shutdown()


# -------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("Welcome to Browser Data Extractor!".center(50))
    print("=" * 50)

    # User selects the browser type
    print("\nChoose browser type:")
    print("1. Chromium-based browsers (e.g., Brave)")
    print("2. Non-Chromium-based browsers (e.g., Firefox, LibreWolf)")
    browser_choice = input("\nEnter your choice (1 or 2): ").strip()

    if browser_choice == '1':
        browser_type = "chromium"
    elif browser_choice == '2':
        browser_type = "non-chromium"
    else:
        print("\n❌ Invalid choice. Please enter '1' or '2'.")
        sys.exit(1)

    if browser_type == "non-chromium":
        try:
            optlist, args = getopt.getopt(sys.argv[1:], 'P')
        except getopt.GetoptError as err:
            print(str(err))
            sys.exit(2)
        # Non-Chromium-based browser options
        print("\nSelect Browser:")
        print("1. Firefox")
        print("2. LibreWolf")
        browser_choice = input("\nEnter your choice (1 or 2): ").strip()

        if browser_choice == '1':
            browser_type = 'firefox'
        elif browser_choice == '2':
            browser_type = 'librewolf'
        else:
            print("\n❌ Invalid choice. Please enter '1' or '2'.")
            sys.exit(1)

        # Get profiles
        ordner = findpath_userdirs(browser_type)
        if not ordner:
            print(f"\n❌ No user profiles found for {browser_type.capitalize()}. Exiting.")
            sys.exit(1)

        # Display profiles and prompt user to choose one
        print(f"\nAvailable profiles for {browser_type.capitalize()}:")
        for idx, user in enumerate(ordner, start=1):
            print(f"{idx}. {os.path.split(user)[-1]}")

        selected_index = int(input(f"\nEnter the number corresponding to the profile you want to select (1-{len(ordner)}): "))
        if selected_index < 1 or selected_index > len(ordner):
            print("\n❌ Invalid selection. Exiting.")
            sys.exit(1)

        selected_user = ordner[selected_index - 1]
        print(f"\n✔ Selected profile: {os.path.split(selected_user)[-1]}")

        use_pass = '-P' in dict(optlist)

        # NSS library setup
        if browser_type == 'librewolf':
            nss_path = r"C:\Program Files\LibreWolf\nss3.dll"
        else:
            nss_path = r"C:\Program Files\Mozilla Firefox\nss3.dll"

        if not os.path.exists(nss_path):
            print(f"Error: nss3.dll not found at {nss_path}")
            sys.exit(1)

        print("Loading NSS library...")
        try:
            libnss = CDLL(nss_path)
            print("Library loaded successfully")
        except OSError as e:
            print(f"Error loading library: {e}")
            sys.exit(1)

        libnss.PK11_GetInternalKeySlot.restype = c_void_p
        libnss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
        libnss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]

        # Get and print installation time
        install_time = get_installation_time(browser_type)
        print(f"Installation Time: {install_time}")
        # Proceed with reading the data for the selected user profile
        signonfiles = glob.glob(os.path.join(selected_user, 'logins.*'))

        if not signonfiles:
            print(f"No login database found in {selected_user}")
            sys.exit(1)

        pw = getpass.getpass("Enter Master Password (or press Enter if none): ") if use_pass else ""
        try:
            with LibNSS(libnss, selected_user):
                readHistory(selected_user)
                readBookmarks(selected_user)
                for sf in signonfiles:
                    readsignonDB(selected_user, os.path.split(sf)[-1], pw, libnss)
                printCacheData(selected_user)
            
                print("\n📥 Download Data:")
                try:
                  readDownloads(selected_user)
                except Exception as e:
                   print(f"❌ Error fetching download data: {e}")
                   
        except RuntimeError as error:
            print(f"❌ {error}")

    elif browser_type == "chromium":
        # Chromium-based browser setup
        # Define Brave paths
        BRAVE_USER_DATA_PATH = os.path.join(os.getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data")
        BRAVE_LOCAL_STATE = os.path.join(BRAVE_USER_DATA_PATH, "Local State")

        print("🦁 Brave Artifact Manager 🦁")
        print("=" * 50)

        # Check if the Brave user data path exists
        if not os.path.exists(BRAVE_USER_DATA_PATH):
            print(f"❌ Brave user data path not found: {BRAVE_USER_DATA_PATH}")
            sys.exit(1)

        # List available profiles
        profiles = list_profiles(BRAVE_USER_DATA_PATH)
        if not profiles:
            print("\n❌ No profiles found for Brave browser. Exiting.")
            sys.exit(1)

        print("\nAvailable profiles for Brave:")
        for i, profile in enumerate(profiles):
            print(f"{i + 1}. {profile}")

        try:
            profile_index = int(input("\nSelect the profile number to extract data from: ")) - 1
            if profile_index < 0 or profile_index >= len(profiles):
                print("\n❌ Invalid selection. Exiting.")
                sys.exit(1)
        except ValueError:
            print("\n❌ Invalid input. Exiting.")
            sys.exit(1)

        # Select the profile
        selected_profile = profiles[profile_index]
        profile_path = os.path.join(BRAVE_USER_DATA_PATH, selected_profile)
        login_data_path = os.path.join(profile_path, "Login Data")
        print(f"\n✔ Selected profile: {selected_profile}")
        
        # Hex view option for the Login Data file
        hex_view_choice = input("\nDo you want to view the Login Data file in hex format? (y/n): ").strip().lower()
        if hex_view_choice == 'y':
           hex_viewer(login_data_path)

        # Get decryption key
        try:
            key = get_decryption_key(BRAVE_LOCAL_STATE)
            print("🔑 Decryption key obtained successfully.")
        except Exception as e:
            print(f"\n❌ Failed to obtain decryption key: {e}")
            sys.exit(1)

        # Fetch and display passwords
        print("\n🔐 Saved Passwords:")
        passwords = fetch_brave_passwords(login_data_path, key)
        if passwords:
           print(f"{'Origin URL':<50} {'Username':<20} {'Password':<20}")
           print("-" * 90)
           for origin_url, username, password in passwords:
              print(f"{origin_url[:48]:<50} {username[:18]:<20} {password:<20}")
        else:
           print("No saved passwords found.")


       # Display bookmarks
        print("\n🔖 Bookmarks:")
        bookmarks = fetch_brave_bookmarks(profile_path)
    
       # Browsing history
        print("\n📜 Browsing History:")
        history = fetch_brave_history(profile_path)


        # Fetch and display cache files
        print("\n🗂️ Cache Files:")
        try:
            cache_files = fetch_brave_cache(profile_path)
            if cache_files:
                for idx, cache_file in enumerate(cache_files, start=1):
                    print(f"{idx}. {cache_file}")

                # Hex view option for cache files
                try:
                    file_choice = int(input("\nEnter the file number to view in hex (or 0 to skip): "))
                    if file_choice > 0 and file_choice <= len(cache_files):
                        hex_viewer(cache_files[file_choice - 1])
                    else:
                        print("No file selected for hex view.")
                except ValueError:
                    print("Invalid input. Skipping hex view.")
            else:
                print("No cache files found.")
        except Exception as e:
            print(f"❌ Error fetching cache files: {e}")

        # Fetch installation date
        software_name = "Brave"
        installed_date = get_installation_date_from_registry(software_name)
        if installed_date:
            print(f"\n📅 Brave Installation Date: {installed_date}")
        else:
            print("\n❌ Installation date not found.")
        
        # Fetch and display downloads
        print("\n📥 Brave Downloads:")
        try:
            downloads = fetch_brave_downloads(profile_path)
            if downloads:
              # Display downloads in a formatted table
              print(f"{'File Path':<60} {'Received':<15} {'Total Size':<15} {'Start Time':<20} {'End Time':<20}")
              print("-" * 130)
              for download in downloads:
                 print(
                 f"{download['target_path'][:58]:<60} "
                 f"{download['received_bytes']:<15} "
                 f"{download['total_bytes']:<15} "
                 f"{download['start_time']:<20} "
                 f"{download['end_time']:<20}"
                 )
 
              # Hex view option for a selected file
              try:
                  file_choice = int(input("\nEnter the number of the download to view in hex (or 0 to skip): "))
                  if file_choice > 0 and file_choice <= len(downloads):
                     selected_file = downloads[file_choice - 1]["target_path"]
                     if os.path.exists(selected_file):
                         hex_viewer(selected_file)
                     else:
                          print("❌ The selected file no longer exists at the specified path.")
                  else:
                      print("No file selected for hex view.")
              except ValueError:
                   print("Invalid input. Skipping hex view.")        
            else:
                print("No downloads found.")
              
        except Exception as e:
           print(f"❌ Error fetching downloads: {e}")
           
         #Display Brave Extensions
        print("\n🔍 Fetching Brave Extensions...")
        fetch_brave_extensions_with_hex(profile_path)
        
        print("\n✔ Data extraction completed successfully!")
        print("=" * 50)
