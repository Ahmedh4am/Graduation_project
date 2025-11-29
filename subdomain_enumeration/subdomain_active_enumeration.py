#pip install dnspython
import dns.resolver #imports the DNS resolving module from the dnspython library.
#  **dns.resolver**  allows Python to perform DNS lookups (A, AAAA, CNAME, MX, TXT, etc).
import os

def check_subdomain(subdomain):
    try:
        dns.resolver.resolve(subdomain, "A")# A--> "A record"-->IPV4
        return True
        #If it didnot work (the dns resolver didnot find anything) it will throw an exception
    except:
        return False

wordlist_file = "Word_lists/mini.txt"


"""
# domian-->The input domain name
# Wordlist_file-->The file with the active enumeration list
def enumerate_subdomains(domain):
    active_subdomains = []

    with open(wordlist_file, "r", encoding="utf-8") as current_file:
        content = current_file.read()
        words = content.split()  #Array of extracted words

    This will split the words on ANY whitespace (space, tab, newline)
    by removing white space and new line indicators
    EX:
    admin <--this is the line
    admin\n <-- this is how it is read
    so it removes ""\n"" and puts "admin" as a clear word in the array



    print(f"[+] Enumerating subdomains for: {domain}\n")

    for word in words:
        subdomain_name = f"{word}.{domain}"#this appends the word from the wordlist(words array) to the input domian name.
        if check_subdomain(subdomain_name):
            print(f"[ACTIVE] {subdomain_name}")
            active_subdomains.append(subdomain_name)
        #If the Check_subdomains returned true it will append this supdomain to the result

    return active_subdomains
"""


def enumerate_subdomains(domain):
    print("[+] Active subdomain Enum ")
    active_subdomains = []

    with open(wordlist_file, "r", encoding="utf-8") as current_file:
        content = current_file.read()
        words = content.split()  #Array of extracted words

    total_domains = len(words)
    domains_tried = 0

    print(f"\t- Enumerating subdomains for: {domain}")
    print(f"\t- Total subdomains to try: {total_domains}")

    for word in words:
        subdomain_name = f"{word}.{domain}"#this appends the word from the wordlist(words array) to the input domian name.
        domains_tried += 1

        # Display progress every 10 domains or on the last one
        if domains_tried % 10 == 0 or domains_tried == total_domains:
            print(f"\t[Progress] DONE {domains_tried}/{total_domains} domains ({domains_tried/total_domains*100:.1f}%)")

        if check_subdomain(subdomain_name):
            # print(f"[ACTIVE] {subdomain_name}")
            active_subdomains.append(subdomain_name)
        #If the Check_subdomains returned true it will append this subdomain to the result

    base_dir = "Results"
    domain_dir = os.path.join(base_dir, f"{domain}_results")
    os.makedirs(domain_dir, exist_ok=True)
    output_file = os.path.join(domain_dir, f"{domain}_Active_Enum_subdomains.txt")

    with open(output_file, "w") as f:
        for sub in active_subdomains:
            f.write(sub + "\n")

    print(f"\t- Found {len(active_subdomains)} subdomains")
    return active_subdomains


def subdomain_printer(domain):
    print("Found Subdomians:\n----------------------------------")
    print(open(f'Results/{domain}_results/{domain}_Active_Enum_subdomains.txt', "r").read())
