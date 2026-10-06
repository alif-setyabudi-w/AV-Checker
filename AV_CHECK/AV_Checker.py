import psutil

SECURITY_PROCESSES = {
    "Microsoft Defender": [
        "MsMpEng.exe"
    ],

    "Ad-Aware": [
        "AdAwareService.exe"
    ],

    "Avast": [
        "afwServ.exe"
    ],

    "Avira": [
        "avguard.exe"
    ],

    "AVG": [
        "AVGSvc.exe"
    ],

    "Bitdefender": [
        "bdagent.exe"
    ],

    "BullGuard": [
        "BullGuardCore.exe"
    ],

    "ESET": [
        "ekrn.exe"
    ],

    "F-Secure": [
        "fshoster32.exe"
    ],

    "G Data": [
        "GDScan.exe"
    ],

    "Kaspersky": [
        "avp.exe"
    ],

    "K7 Security": [
        "K7CrvSvc.exe"
    ],

    "McAfee": [
        "McAPExe.exe"
    ],

    "Norton": [
        "NortonSecurity.exe"
    ],

    "Panda": [
        "PavFnSvr.exe"
    ],

    "Sophos": [
        "SavService.exe"
    ],

    "Trellix / Enterprise Security": [
        "EnterpriseService.exe"
    ],

    "Webroot": [
        "WRSA.exe"
    ],

    "ZoneAlarm": [
        "ZAPrivacyService.exe"
    ]
}


def check_security_software():
    detected = []

    print("[+] Security Software Checker")
    print("[+] Scanning running processes...\n")

    for process in psutil.process_iter(["name", "pid"]):
        try:
            process_name = process.info["name"]
            process_pid = process.info["pid"]

            for vendor, processes in SECURITY_PROCESSES.items():

                if process_name in processes:
                    result = {
                        "vendor": vendor,
                        "process": process_name,
                        "pid": process_pid
                    }

                    detected.append(result)

                    print(f"[+] Security software found")
                    print(f"    Vendor  : {vendor}")
                    print(f"    Process : {process_name}")
                    print(f"    PID     : {process_pid}")
                    print()

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return detected


def main():
    detected = check_security_software()

    print("----------------------------------------")

    if detected:
        print(f"[+] Detection completed")
        print(f"[+] Security software found: {len(detected)}")
    else:
        print("[-] No matching security software found.")


if __name__ == "__main__":
    main()