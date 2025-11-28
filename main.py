from subdomain_enumeration.subdomain_active_enumeration import enumerate_subdomains ,subdomain_printer


def main():
    domain = input("Enter domain: ").strip()
    enumerate_subdomains(domain)
    subdomain_printer(domain)



if __name__ == "__main__":
    main()

