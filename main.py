from detector.scanner import PhishingScanner
def main():
    print("=== URL Phishing Detector Started ===")
    scanner = PhishingScanner()
    while True:
        user_url=input("\nEnter a URL to check(or type 'quit' to exit):")
        if user_url.lower()=='quit':
            print("Goodbye")
            break
        results=scanner.scan_url(user_url)
        if not results:
            print("This URL looks safe based on our current rules.")
        else:
            print("WARNING! Suspicious patterns found:")
            for issue in results:
                print(f" - {issue}")
if __name__=="__main__":
    main()