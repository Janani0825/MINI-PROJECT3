"""Download the public datasets once (needs internet). Afterwards everything runs offline."""
import os
import urllib.request

FILES = {
    # real, currently-active phishing URLs (Phishing.Database project)
    "phishing-links-ACTIVE.txt":
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    # popular (legitimate) domains
    "top-1000000-domains":
        "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains",
    # legitimate URLs that include paths
    "1.Benign_list_big_final.csv":
        "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/1.Benign_list_big_final.csv",
}
os.makedirs("data", exist_ok=True)
for name, url in FILES.items():
    dest = os.path.join("data", name)
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        print("already have", name); continue
    print("downloading", name, "...")
    urllib.request.urlretrieve(url, dest)
print("done")
