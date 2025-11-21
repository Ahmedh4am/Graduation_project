#pip install dnspython
import dns.resolver #imports the DNS resolving module from the dnspython library.
#  **dns.resolver**  allows Python to perform DNS lookups (A, AAAA, CNAME, MX, TXT, etc).


def check_subdomain(subdomain):
    try:
        dns.resolver.resolve(subdomain, "A")# A--> "A record"-->IPV4
        return True
        #If it didnot work (the dns resolver didnot find anything) it will throw an exception
    except:
        return False

wordlist_file = "Word_lists/active_subdomian_enumeration_word_list.txt"



# domian-->The input domain name
# Wordlist_file-->The file with the active enumeration list
def enumerate_subdomains(domain):
    active_subdomains = []

    with open(wordlist_file, "r", encoding="utf-8") as current_file:
        content = current_file.read()
        words = content.split()  #Array of extracted words
    """
    This will split the words on ANY whitespace (space, tab, newline)
    by removing white space and new line indicators
    EX:
    admin <--this is the line
    admin\n <-- this is how it is read
    so it removes ""\n"" and puts "admin" as a clear word in the array

    """

    print(f"[+] Enumerating subdomains for: {domain}\n")

    for word in words:
        subdomain_name = f"{word}.{domain}"#this appends the word from the wordlist(words array) to the input domian name.
        if check_subdomain(subdomain_name):
            print(f"[ACTIVE] {subdomain_name}")
            active_subdomains.append(subdomain_name)
        #If the Check_subdomains returned true it will append this supdomain to the result

    return active_subdomains
