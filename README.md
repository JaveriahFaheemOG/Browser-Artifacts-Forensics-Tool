## **Browser Artifacts Forensics Tool for Privacy-Focused Browsers** ##

## **Disclaimer**

This repository is intended for **educational and research purposes only**.  
The tools and scripts provided are designed for use in **controlled, authorized environments**.  
**Any misuse is strictly prohibited.**  
The author is not responsible for any damage caused by the use of this code.

This tool is designed for digital forensics investigations of privacy-focused browsers such as **Brave** and **Tor**. It extracts and analyzes browser artifacts, including browsing history, stored passwords, cache files, bookmarks, extensions, downloads, and installation details from the Windows registry.

## **Purpose**

This tool is designed for digital forensics investigations of privacy-focused browsers such as **Brave** and **Tor**. It extracts and analyzes browser artifacts, including browsing history, stored passwords, cache files, bookmarks, extensions, downloads, and installation details from the Windows registry.
The purpose of this tool is to assist forensic investigators in retrieving sensitive data from these browsers, which may be important for various investigations, such as privacy-related cases or user activity tracking.

## **Key Features**

1. **Browsing History Extraction**:  
   * Retrieves the browsing history of the user, including URLs visited and associated timestamps.  
2. **Bookmark Extraction**:  
   * Extracts information about the bookmarks saved in the browser.  
3. **Stored Password Extraction**:  
   * Retrieves stored passwords, if accessible, from the browser's encrypted database (where possible).  
4. **Cache File Retrieval**:  
   * Fetches cached files from the browser, with an option to view the contents in a hexadecimal format.  
5. **Download History Extraction**:  
   * Lists downloaded files with details like file path, received bytes, total size, and timestamps for start and end of the download.  
6. **Extension Information**:  
   * Fetches information about installed browser extensions, which could include potentially useful forensic evidence.  
7. **Browser Installation Date**:  
   * Retrieves the installation date of the browser from the Windows registry, which can be helpful for timeline analysis.

## **Dependencies**

This tool requires Python 3.7 or higher and the following Python libraries:

* `os`  
* `sqlite3`  
* `glob`  
* `pycryptodome`  
* `struct`  
* `hexviewer` (or an equivalent tool for viewing hex files)

### **To install the necessary dependencies:**

`pip install pycryptodome hexviewer`
`pip install pywincrypt32`

## **Installation Instructions**

Follow the steps below to install and set up the tool:

1. **Connect the USB Drive** (that contains the tool) to your system.

2. **Install Python 3.7 or Higher**  
Ensure that Python 3.7 or a later version is installed. You can check your Python version by running:

`python --version`

 If needed, download and install Python from [python.org](https://www.python.org).

3. **Set Up a Virtual Environment (Optional but Recommended)**  
It is highly recommended to create a virtual environment to manage dependencies for the tool. To set up a virtual environment, run the following commands:

`python -m venv venv`

Activate the virtual environment:  
   * For **Windows**:

     `venv\Scripts\activate`  
   * For **macOS/Linux**:

     `source venv/bin/activate`

4. **Install Required Dependencies**  
After activating the virtual environment or directly running on terminal, install the required Python libraries:

* Check if pip is already installed  
  **`python -m pip --version`**


If `pip` is already installed, you will see a version number like `pip 24.x.x`. If you get an error, proceed with the installation steps.

* Install pip on Windows (if not already installed)

  #### **Step 1: Download `get-pip.py`**

1. Open your web browser and go to the following URL: [https://bootstrap.pypa.io/get-pip.py](https://bootstrap.pypa.io/get-pip.py)  
2. Right-click and choose **Save As** to save the `get-pip.py` file to a location on your computer (e.g., the Desktop).

   #### **Step 2: Run the Script to Install pip**

1. Open Command Prompt (Press `Windows + R`, then type `cmd` and hit Enter).  
2. Navigate to the directory where you saved `get-pip.py` (e.g., `cd Desktop` if you saved it on the desktop).  
3. Run the following command to install `pip`:  
          **`python get-pip.py`**

This will install `pip` for Python.

* ### Verify the Installation

After installation, verify that `pip` is installed:

      ** `pip --version`**

This should show the version of `pip` installed.

* ### Add Python and pip to PATH (if necessary)

If you encounter an error like `'pip' is not recognized as an internal or external command`, it means that Python or pip might not be added to your system's PATH. To fix this:

1. Find the location of Python on your system (e.g., `C:\Python311`).  
2. Open the **Start Menu** and search for **Environment Variables**.  
3. Click on **Edit the system environment variables**.  
4. In the **System Properties** window, click on **Environment Variables**.  
5. Under **System variables**, scroll to find the **Path** variable, select it, and click **Edit**.  
6. Add the following paths (adjust them based on your Python installation directory):  
   * `C:\Python311\Scripts`  
   * `C:\Python311\`

Alternatively, install the necessary packages individually:

 `pip install pycryptodome hexviewer`

5. **Run the Tool**  
   Once all dependencies are installed, run the tool using the following command:

   `python tool.py`

## **How to Use**

1. **Select User Profile**  
   * Choose the user profile from which the artifacts will be extracted.  
2. **Select the Browser**  
   * Choose browser from the available options.  
3. **Select Artifacts to Analyze**  
   * Once the profile path is provided, the tool will begin extracting various browser artifacts. You will be presented with options to analyze:  
     * Browsing History  
     * Bookmarks  
     * Stored Passwords  
     * Cache Files  
     * Download History  
     * Installed Extensions  
4. **Hexadecimal File Viewing**  
   * For all the artifacts, you will be given the option to view the file contents in hexadecimal format. You can choose to do so by entering the file number when prompted. Hexadecimal viewing is useful for detailed forensic analysis.

## **Troubleshooting**

### **1\. Missing Dependencies**

If you encounter errors about missing libraries, ensure that all dependencies are installed:

`pip install pycryptodome hexviewer`

### **2\. Permission Issues**

On certain systems, you may need elevated privileges to read files from certain directories (such as system profiles or encrypted browser storage). If you face permission errors, try the following:

* **Run the tool with administrator privileges**:  
  Right-click the command prompt and select **Run as Administrator**.  
* **Check file permissions**:  
  Ensure the user running the tool has permission to access the browser profile directories (e.g., Brave or Tor).

### **3\. Incompatible Python Version**

The tool requires Python 3.7 or higher. To check the Python version:

`python --version`

If you are using an older version of Python, consider upgrading to a newer version (3.7 or above).

### **4\. Missing or Corrupted Files**

If the tool doesn't find certain files (e.g., the SQLite databases or the cache files), ensure the browser is actively using the profile you're analyzing. If the user has cleared their history or other artifacts, some data might not be retrievable.

### **5\. Hexadecimal File Viewing Issues**

For cache files and other binary files, you may run into display issues. Ensure you have the `hexviewer` library installed properly. If you encounter problems with it, you can try installing an alternative tool or manually inspect the file in a hex editor.

### **6\. Browser Encryption/Decryption Issues**

If the tool fails to decrypt stored passwords, it's likely due to the browser's use of encryption. In such cases, make sure that the `pycryptodome` library is correctly installed and that the necessary decryption keys are accessible.

## **Additional Notes**

* **Forensic Investigation Compliance**:  
  Ensure that the use of this tool adheres to the legal requirements of your region, including obtaining consent or legal authorization to access and extract browser artifacts from the system being investigated.  
* **Data Integrity**:  
  The tool is designed to be non-intrusive, meaning it doesn’t alter the data it extracts. However, always ensure you are working with copies of the data (for example, cloned disks or disk images) to avoid tampering with evidence.

## **Authors**
Abubakkar Sharif - FAST NUCES
Javeriah Faheem  - FAST NUCES
Sabreena Azhar   - FAST NUCES
Umar Zeb         - FAST NUCES
