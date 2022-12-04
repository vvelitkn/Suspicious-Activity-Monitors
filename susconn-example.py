import requests

# Send the request to the Google.com website
response = requests.get("https://www.google.com")

# Print the response
print("Response status code:", response.status_code)
print("Response content:")
print(response.content)
