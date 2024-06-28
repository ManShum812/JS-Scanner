# Overview
This is a script I've developed to scan a bunch of JS URLs provided in a .txt file for sensitive data like passwords, tokens, and keys. It fetches content from the URLs and searches for various types of sensitive information.

# Features
Concurrent Scanning: Utilizes a thread pool to scan multiple URLs concurrently for faster results.

Comprehensive Patterns: Includes a wide range of regular expressions to identify various types of sensitive data.

Detailed Logging: Logs the scanning process and results, providing clear information on any issues encountered.

Efficient Requests: Uses HTTP HEAD requests to check URL status before fetching content, saving time and resources.

# Installation and Usage:
Install Dependencies: Ensure requests is installed (pip install requests).

Prepare Input File: Create a file named input_urls.txt with the URLs you want to scan, one per line.

Run the Script: python js.py

Output: The results will be saved in output_results.txt. The file will contain details about any sensitive data found, including the type of data and the matched pattern.
![111](https://github.com/ManShum812/JS-Scanner/assets/43279996/df2745b1-beb4-4b43-97a8-3bafaf0f4a47)


# Get Involved
Your contributions are welcome! You can help improve this project by opening issues or submitting pull requests. If you have any ideas to enhance the tool, please share them. Together, we can make the web a safer place!
