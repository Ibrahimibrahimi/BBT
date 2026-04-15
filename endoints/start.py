import webbrowser
import os

# Path to your HTML file
html_file_path = 'api_leaks_scanner.html'

# Convert file path to a URL
file_url = 'file://' + os.path.abspath(html_file_path)

# Open in default web browser
webbrowser.open(file_url)