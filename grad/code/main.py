from subdomain_enumeration.subdomain_active_enumeration import enumerate_subdomains


def main():
    domain = input("Enter domain: ").strip()
    found_subdomians = enumerate_subdomains(domain)

    print("\n---- RESULTS ----")
    for subdomian_found in found_subdomians:
        print(subdomian_found)


if __name__ == "__main__":
    main()
